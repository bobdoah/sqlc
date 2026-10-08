package wasm

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestFetchOCIWithDockerCredentials(t *testing.T) {
	wasm := []byte("\x00asm\x01\x00\x00\x00")
	layer := ocispec.Descriptor{
		MediaType: wasmLayerMediaType,
		Digest:    digest.FromBytes(wasm),
		Size:      int64(len(wasm)),
	}
	manifest, err := json.Marshal(ocispec.Manifest{
		Versioned: ocispec.Manifest{}.Versioned,
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.wasm.config.v1+json",
			Digest:    digest.FromBytes(nil),
			Size:      0,
		},
		Layers: []ocispec.Descriptor{layer},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest.FromBytes(manifest)

	const username = "sqlc"
	const password = "secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPassword, ok := r.BasicAuth()
		if !ok || gotUser != username || gotPassword != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/plugins/sqlc/manifests/v1":
			w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
			w.Header().Set("Docker-Content-Digest", manifestDigest.String())
			_, _ = w.Write(manifest)
		case "/v2/plugins/sqlc/blobs/" + layer.Digest.String():
			w.Header().Set("Content-Type", wasmLayerMediaType)
			w.Header().Set("Docker-Content-Digest", layer.Digest.String())
			_, _ = w.Write(wasm)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dockerConfig := t.TempDir()
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	config := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, serverURL.Host, auth)
	if err := os.WriteFile(filepath.Join(dockerConfig, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dockerConfig)

	got, err := fetchOCI(context.Background(), "oci://"+serverURL.Host+"/plugins/sqlc:v1", true)
	if err != nil {
		t.Fatal(err)
	}
	if gotSum, wantSum := sha256.Sum256(got), sha256.Sum256(wasm); gotSum != wantSum {
		t.Fatalf("WASM checksum = %x, want %x", gotSum, wantSum)
	}
}

func TestWASMLayer(t *testing.T) {
	want := ocispec.Descriptor{MediaType: wasmLayerMediaType, Digest: digest.FromString("wasm")}
	layers := []ocispec.Descriptor{
		{MediaType: "application/octet-stream", Digest: digest.FromString("other")},
		want,
	}
	got, err := wasmLayer(layers)
	if err != nil {
		t.Fatal(err)
	}
	if got.MediaType != want.MediaType || got.Digest != want.Digest {
		t.Fatalf("wasmLayer() = %v, want %v", got, want)
	}
	if _, err := wasmLayer(layers[:1]); err != nil {
		t.Fatalf("single-layer artifact was rejected: %v", err)
	}
	if _, err := wasmLayer(layers); err != nil {
		t.Fatalf("artifact with a WASM layer was rejected: %v", err)
	}
	if _, err := wasmLayer([]ocispec.Descriptor{layers[0], layers[0]}); err == nil {
		t.Fatal("multi-layer artifact without a WASM layer was accepted")
	}
}
