package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolvedRequirements(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/releases/rel-1/requirements/resolved" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"cr":{"value":"H","level":"release"},"ir":{"value":"M","level":"product"},"ar":{"value":"X","level":"default"}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, srv.Client())
	got, err := c.ResolvedRequirements(context.Background(), "rel-1")
	if err != nil || got.CR.Value != "H" || got.CR.Level != "release" || got.IR.Level != "product" || got.AR.Value != "X" {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := c.ResolvedRequirements(context.Background(), "other"); err == nil {
		t.Error("404 swallowed")
	}
}
