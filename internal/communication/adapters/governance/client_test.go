package governance_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/governance"
	"github.com/themis-project/themis/internal/communication/domain"
)

func TestGetPosition(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/findings/fnd-1":
			_, _ = w.Write([]byte(`{
				"id":"fnd-1","release_id":"rel-1","faultline_id":"fl-1","cve":"CVE-2024-1",
				"current_position":{"version":2,"stance":"not_affected","rationale":"vendor VEX confirms"}
			}`))
		case "/api/v1/findings/no-position":
			_, _ = w.Write([]byte(`{"id":"no-position","release_id":"rel-2","faultline_id":"fl-2","cve":"CVE-2"}`))
		case "/api/v1/findings/bad-json":
			_, _ = w.Write([]byte(`{not json`))
		case "/api/v1/findings/boom":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := governance.NewClient(srv.URL, srv.Client())
	ctx := context.Background()

	// Happy path.
	snap, found, err := c.GetPosition(ctx, "fnd-1")
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if snap.Version != 2 || snap.Stance != domain.StanceNotAffected || snap.Rationale != "vendor VEX confirms" {
		t.Errorf("snapshot = %+v", snap)
	}
	if snap.Lineage.ReleaseID != "rel-1" || snap.Lineage.FaultlineID != "fl-1" || snap.Lineage.CVE != "CVE-2024-1" {
		t.Errorf("lineage = %+v", snap.Lineage)
	}

	// Finding exists but has no decision → not found.
	if _, found, err := c.GetPosition(ctx, "no-position"); err != nil || found {
		t.Errorf("no-position: found=%v err=%v", found, err)
	}
	// Unknown finding (404) → not found.
	if _, found, err := c.GetPosition(ctx, "unknown"); err != nil || found {
		t.Errorf("unknown: found=%v err=%v", found, err)
	}
	// Server error → error.
	if _, _, err := c.GetPosition(ctx, "boom"); err == nil {
		t.Error("server error: expected error")
	}
	// Malformed body → error.
	if _, _, err := c.GetPosition(ctx, "bad-json"); err == nil {
		t.Error("bad json: expected error")
	}
}

func TestGetPosition_TransportError(t *testing.T) {
	// A closed server yields a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	if _, _, err := governance.NewClient(url, nil).GetPosition(context.Background(), "fnd-1"); err == nil {
		t.Error("transport error: expected error")
	}
}
