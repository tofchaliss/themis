package wiring_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/wiring"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// Wiring is no gate (EDR-SECURITY-01, 2026-10-13): a client that CAN send the key proves
// nothing until the composition root hands it one. This drives a real Invoke against a
// Governance node that requires `X-API-Key` and asserts the projection read authenticated —
// the Gateway's only business read, and the whole of its grounding.
func TestWireSendsTheNodeAPIKeyOnTheGovernanceRead(t *testing.T) {
	const nodeKey = "intelligence-node-key"
	projection := `{"finding":{"id":"F1","release_id":"rel-1","faultline_id":"FL1",
		"cve":"CVE-2026-1","stage":"identified","components":[{"purl":"pkg:golang/openssl"}]},
		"knowledge":{"faultline_id":"FL1","cve":"CVE-2026-1","severity":"high"}}`

	var seen []string
	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-API-Key"))
		if r.Header.Get("X-API-Key") != nodeKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(projection))
	}))
	defer gov.Close()

	// invoke wires a Gateway with the given node key, runs one recommend_position, and returns
	// the outcome reason plus the headers this invocation's reads carried.
	invoke := func(key string) (string, []string) {
		t.Helper()
		seen = nil
		intel, err := wiring.Wire(wiring.Config{
			GovernanceURL: gov.URL, UseFake: true, NodeAPIKey: key, HTTPClient: gov.Client(),
		})
		if err != nil {
			t.Fatalf("wire: %v", err)
		}
		_, out := intel.Gateway.Invoke(context.Background(), "recommend_position",
			domain.Selection{Type: domain.SelectionFinding, IDs: []string{"F1"}}, "corr-1")
		return out.Reason, seen
	}

	reason, headers := invoke(nodeKey)
	if reason == "no_grounding" {
		t.Errorf("reason = %q — an authenticated Gateway must reach its grounding", reason)
	}
	if len(headers) == 0 {
		t.Fatal("the Gateway made no Governance read at all")
	}
	for i, got := range headers {
		if got != nodeKey {
			t.Errorf("read %d sent X-API-Key %q, want the node key — this seam is not wired", i, got)
		}
	}

	// Without the key the projection read is refused, and the Gateway can only report
	// no-grounding — the outcome that is indistinguishable from an estate with nothing to say,
	// which is why the credential must be WIRED and not merely supported.
	reason, headers = invoke("")
	if reason != "no_grounding" {
		t.Errorf("reason = %q, want no_grounding when the read is unauthenticated", reason)
	}
	for i, got := range headers {
		if got != "" {
			t.Errorf("read %d sent X-API-Key %q, want none when no key is configured", i, got)
		}
	}
}
