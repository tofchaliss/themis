package readapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
)

// The Registry walk: products → projects → releases, flattened to every release id.
func TestListReleaseIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/products":
			_, _ = w.Write([]byte(`[{"id":"prod-1"}]`))
		case strings.HasSuffix(r.URL.Path, "/projects"):
			_, _ = w.Write([]byte(`[{"id":"proj-1"},{"id":"proj-2"}]`))
		case strings.HasSuffix(r.URL.Path, "/releases"):
			_, _ = w.Write([]byte(`[{"id":"rel-a"},{"id":"rel-b"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ids, err := readapi.NewRegistryClient(srv.URL, srv.Client()).ListReleaseIDs(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// 1 product × 2 projects × 2 releases = 4.
	if len(ids) != 4 {
		t.Fatalf("ids = %v, want 4", ids)
	}
}

func TestListReleaseIDs_ReadErrorAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := readapi.NewRegistryClient(srv.URL, srv.Client()).ListReleaseIDs(context.Background()); err == nil {
		t.Error("a read failure must abort the walk (no partial estate)")
	}
}

func TestListReleaseIDs_MalformedAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()
	if _, err := readapi.NewRegistryClient(srv.URL, nil).ListReleaseIDs(context.Background()); err == nil {
		t.Error("malformed JSON must abort")
	}
}
