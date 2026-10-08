package wasm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/sqlc-dev/sqlc/internal/info"
)

const wasmLayerMediaType = "application/vnd.wasm.content.layer.v1+wasm"

func fetchOCI(ctx context.Context, uri string, plainHTTP bool) ([]byte, error) {
	reference := strings.TrimPrefix(uri, "oci://")
	repo, err := remote.NewRepository(reference)
	if err != nil {
		return nil, fmt.Errorf("parse OCI reference %q: %w", uri, err)
	}
	repo.PlainHTTP = plainHTTP

	store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err != nil {
		return nil, fmt.Errorf("load Docker credentials: %w", err)
	}
	client := &auth.Client{
		Client:     retry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: credentials.Credential(store),
	}
	client.SetUserAgent(fmt.Sprintf("sqlc/%s Go/%s (%s %s)", info.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH))
	repo.Client = client

	desc, manifestReader, err := repo.FetchReference(ctx, repo.Reference.Reference)
	if err != nil {
		return nil, fmt.Errorf("fetch OCI manifest %q: %w", uri, err)
	}
	defer manifestReader.Close()
	if desc.MediaType != ocispec.MediaTypeImageManifest && desc.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		return nil, fmt.Errorf("OCI reference %q resolved to unsupported media type %q", uri, desc.MediaType)
	}
	manifestData, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, fmt.Errorf("read OCI manifest %q: %w", uri, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("decode OCI manifest %q: %w", uri, err)
	}
	layer, err := wasmLayer(manifest.Layers)
	if err != nil {
		return nil, fmt.Errorf("OCI artifact %q: %w", uri, err)
	}

	body, err := repo.Fetch(ctx, layer)
	if err != nil {
		return nil, fmt.Errorf("fetch OCI WASM layer %q: %w", uri, err)
	}
	defer body.Close()
	wmod, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read OCI WASM layer %q: %w", uri, err)
	}
	return wmod, nil
}

func wasmLayer(layers []ocispec.Descriptor) (ocispec.Descriptor, error) {
	for _, layer := range layers {
		if layer.MediaType == wasmLayerMediaType {
			return layer, nil
		}
	}
	if len(layers) == 1 {
		return layers[0], nil
	}
	return ocispec.Descriptor{}, fmt.Errorf("manifest must contain a %q layer or exactly one layer", wasmLayerMediaType)
}
