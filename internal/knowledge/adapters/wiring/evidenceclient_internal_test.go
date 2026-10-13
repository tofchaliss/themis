package wiring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Knowledge's Evidence read seam must carry THEMIS_API_KEY, or an Evidence node with auth on
// answers 401 and an uploaded SBOM correlates to nothing — the first-hop stall that kept
// Evidence running AUTH DISABLED on the enterprise VM (2026-10-13). Wire builds its one client
// through this constructor, so testing it here is testing what the node actually sends.
func TestEvidenceClient_SendsAPIKeyOnlyWhenSet(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("X-API-Key"))
		_, _ = w.Write([]byte(`{"components":[]}`))
	}))
	defer srv.Close()

	for _, key := range []string{" read-key\n", ""} {
		if _, err := evidenceClient(srv.URL, key).GetInventory(context.Background(), "ev-1"); err != nil {
			t.Fatalf("inventory with key %q: %v", key, err)
		}
	}
	if len(got) != 2 || got[0] != "read-key" || got[1] != "" {
		t.Fatalf("X-API-Key sent = %q, want [read-key, \"\"] (trimmed key, then none)", got)
	}
}
