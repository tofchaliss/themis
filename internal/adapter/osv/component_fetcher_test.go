package osv_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/adapter/osv"
	"github.com/themis-project/themis/internal/domain"
)

func TestComponentFetcherSkipsUnsupportedEcosystem(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client := osv.NewClient(osv.ClientConfig{BaseURL: srv.URL, RateLimiter: osv.NewTokenBucket(100, 100)})
	fetcher := osv.ComponentFetcher{Client: client}
	out, err := fetcher.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "rpm",
		Name:      "openssl",
		Version:   "1.1.1",
	})
	if err != nil {
		t.Fatalf("FetchForComponent() error = %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("records = %#v", out)
	}
	if called {
		t.Fatal("expected unsupported ecosystem to skip osv request")
	}
}
