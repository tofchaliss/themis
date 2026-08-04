package embed_test

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/embed"
)

func cosine(a, b []float32) float64 {
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func TestFakeEmbedderIsDeterministic(t *testing.T) {
	e := embed.NewFakeEmbedder(256)
	a, _ := e.Embed(context.Background(), "openssl heap overflow in TLS handshake")
	b, _ := e.Embed(context.Background(), "openssl heap overflow in TLS handshake")
	if len(a) != 256 {
		t.Fatalf("dim: got %d want 256", len(a))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("not deterministic at %d: %v != %v", i, a[i], b[i])
		}
	}
}

func TestFakeEmbedderSimilarityTracksTokenOverlap(t *testing.T) {
	e := embed.NewFakeEmbedder(512)
	ctx := context.Background()
	q, _ := e.Embed(ctx, "openssl heap buffer overflow in TLS")
	near, _ := e.Embed(ctx, "openssl buffer overflow in TLS handshake")
	far, _ := e.Embed(ctx, "python yaml unsafe deserialization bug")

	simNear := cosine(q, near)
	simFar := cosine(q, far)
	if simNear <= simFar {
		t.Fatalf("expected the overlapping text to be nearer: near=%.3f far=%.3f", simNear, simFar)
	}
}

func TestFakeEmbedderEmptyTextIsZeroVector(t *testing.T) {
	e := embed.NewFakeEmbedder(0) // defaults to 64
	v, err := e.Embed(context.Background(), "   ,.! ")
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if len(v) != 64 {
		t.Fatalf("dim: got %d want default 64", len(v))
	}
	for i, x := range v {
		if x != 0 {
			t.Fatalf("expected zero vector, non-zero at %d: %v", i, x)
		}
	}
}

func TestFakeEmbedderModel(t *testing.T) {
	if got := embed.NewFakeEmbedder(8).Model(); got != "fake-hash" {
		t.Fatalf("model: got %q want %q", got, "fake-hash")
	}
}

func TestOllamaEmbedderHappyPath(t *testing.T) {
	var gotBody embeddingsReq
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"embedding": []float32{0.1, 0.2, 0.3}}},
		})
	}))
	defer srv.Close()

	e := embed.NewOllamaEmbedder(srv.URL, "nomic-embed-text", srv.Client()).WithAPIKey("secret")
	v, err := e.Embed(context.Background(), "hello")
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if len(v) != 3 || v[0] != 0.1 || v[2] != 0.3 {
		t.Fatalf("vector: got %v", v)
	}
	if gotPath != "/v1/embeddings" {
		t.Errorf("path: got %q", gotPath)
	}
	if gotBody.Model != "nomic-embed-text" || gotBody.Input != "hello" {
		t.Errorf("request body: got %+v", gotBody)
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("auth header: got %q", gotAuth)
	}
	if e.Model() != "nomic-embed-text" {
		t.Errorf("model: got %q", e.Model())
	}
}

func TestOllamaEmbedderNoAuthHeaderWithoutKey(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"embedding": []float32{1}}},
		})
	}))
	defer srv.Close()

	if _, err := embed.NewOllamaEmbedder(srv.URL, "m", srv.Client()).Embed(context.Background(), "x"); err != nil {
		t.Fatalf("embed: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("expected no Authorization header, got %q", gotAuth)
	}
}

func TestOllamaEmbedderErrorPaths(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		payload string
	}{
		{"non-200", http.StatusInternalServerError, `{"error":"boom"}`},
		{"empty-data", http.StatusOK, `{"data":[]}`},
		{"empty-embedding", http.StatusOK, `{"data":[{"embedding":[]}]}`},
		{"bad-json", http.StatusOK, `not json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.payload)
			}))
			defer srv.Close()
			if _, err := embed.NewOllamaEmbedder(srv.URL, "m", srv.Client()).Embed(context.Background(), "x"); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestOllamaEmbedderRequestFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // closed server → connection refused
	if _, err := embed.NewOllamaEmbedder(srv.URL, "m", srv.Client()).Embed(context.Background(), "x"); err == nil {
		t.Fatal("expected a request-failure error against a closed server")
	}
}

// embeddingsReq mirrors the wire request shape the handler asserts against.
type embeddingsReq struct {
	Model string `json:"model"`
	Input string `json:"input"`
}
