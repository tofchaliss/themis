package readapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/readapi"
)

// The inbound-edge credential of EDR-SECURITY-01 F1, asserted once per client in this package:
// every inter-service call carries `X-API-Key` when the node has a key, and NO header when it
// does not. The four clients share one fake peer because they share one remedy — THEMIS_API_KEY
// on the Intelligence node — and a per-client copy of this server would let them drift.

const nodeKey = "intelligence-node-key-abc123"

// authedPeer answers 401 to any request that does not carry nodeKey (a Governance or Registry
// node running with THEMIS_AUTH_DATABASE_DSN set), and records the header it saw on each
// request so an absent key can be asserted as an ABSENT header rather than a refused call.
func authedPeer(t *testing.T, bodies map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-API-Key"))
		if r.Header.Get("X-API-Key") != nodeKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// assertSentKey checks that every request the peer saw carried the configured key.
func assertSentKey(t *testing.T, seen *[]string, want int) {
	t.Helper()
	if len(*seen) != want {
		t.Fatalf("saw %d requests, want %d", len(*seen), want)
	}
	for i, got := range *seen {
		if got != nodeKey {
			t.Errorf("request %d sent X-API-Key %q, want the configured key", i, got)
		}
	}
}

// The grounding read (the Gateway's ONLY business read). Without the credential the Gateway can
// only report no-grounding, which is indistinguishable from an estate with nothing to say —
// the one confusion a grounding seam must not create.
func TestAssessmentClientSendsAPIKeyOnlyWhenSet(t *testing.T) {
	bodies := map[string]string{
		"/api/v1/findings/F1/assessment": `{"finding":{"id":"F1"},"knowledge":{"cve":"CVE-2024-0001"}}`,
		"/api/v1/releases/R1/posture":    `[{"finding_id":"F1","cve":"CVE-2024-0001"}]`,
		"/api/v1/releases/R1/compare/R2": `{"baseline_release_id":"R1","candidate_release_id":"R2"}`,
	}
	srv, seen := authedPeer(t, bodies)
	c := readapi.NewAssessmentClient(srv.URL, srv.Client()).WithAPIKey("  " + nodeKey + "\n") // trimmed

	if _, err := c.GetAssessment(context.Background(), "F1"); err != nil {
		t.Errorf("assessment: %v", err)
	}
	if _, err := c.GetReleasePosture(context.Background(), "R1"); err != nil {
		t.Errorf("posture: %v", err)
	}
	if _, err := c.GetReleaseComparison(context.Background(), "R1", "R2"); err != nil {
		t.Errorf("compare: %v", err)
	}
	assertSentKey(t, seen, 3)

	// Unset: no header at all, and the failure names the variable.
	srv2, seen2 := authedPeer(t, bodies)
	_, err := readapi.NewAssessmentClient(srv2.URL, srv2.Client()).GetAssessment(context.Background(), "F1")
	if err == nil {
		t.Fatal("an unauthenticated projection read must fail")
	}
	for _, want := range []string{"401", "sent no X-API-Key", "THEMIS_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
	if len(*seen2) != 1 || (*seen2)[0] != "" {
		t.Errorf("headers seen = %q, want one request carrying no X-API-Key", *seen2)
	}

	// A refused key is a different operator problem from an absent one, and the credential is
	// never echoed.
	_, err = readapi.NewAssessmentClient(srv2.URL, srv2.Client()).WithAPIKey("stale-key").
		GetAssessment(context.Background(), "F1")
	if err == nil || !strings.Contains(err.Error(), "Governance refused") {
		t.Errorf("err = %v, want it to distinguish a refused key from an absent one", err)
	}
	if strings.Contains(err.Error(), "stale-key") {
		t.Errorf("err = %v leaked the credential", err)
	}
}

// A 404 carries NO credential advice: the assessment client's own not-found path must stay
// readable as "no such Finding".
func TestAssessmentClientCredentialHintOnlyOnAuthFailures(t *testing.T) {
	srv, _ := authedPeer(t, map[string]string{})
	_, err := readapi.NewAssessmentClient(srv.URL, srv.Client()).WithAPIKey(nodeKey).
		GetAssessment(context.Background(), "F1")
	if err == nil || strings.Contains(err.Error(), "THEMIS_API_KEY") {
		t.Errorf("err = %v, want a plain 404 with no credential advice", err)
	}
}

// The exact-CVE precedent fallback. Two hops (blast-radius then find-by-key), both credentialed.
func TestPrecedentClientSendsAPIKeyOnlyWhenSet(t *testing.T) {
	bodies := map[string]string{
		"/api/v1/faultlines/FL1/blast-radius": `["R1"]`,
		"/api/v1/findings":                    `{"current_position":{"stance":"not_affected","rationale":"backported"}}`,
	}
	srv, seen := authedPeer(t, bodies)
	got, err := readapi.NewPrecedentClient(srv.URL, srv.Client()).WithAPIKey(nodeKey).
		GetPrecedents(context.Background(), "FL1", "R0")
	if err != nil {
		t.Fatalf("precedents: %v", err)
	}
	if len(got) != 1 || got[0].Stance != "not_affected" {
		t.Errorf("precedents = %+v", got)
	}
	assertSentKey(t, seen, 2)

	srv2, seen2 := authedPeer(t, bodies)
	_, err = readapi.NewPrecedentClient(srv2.URL, srv2.Client()).
		GetPrecedents(context.Background(), "FL1", "R0")
	if err == nil || !strings.Contains(err.Error(), "THEMIS_API_KEY") {
		t.Errorf("err = %v, want the credential hint", err)
	}
	if len(*seen2) != 1 || (*seen2)[0] != "" {
		t.Errorf("headers seen = %q, want one request carrying no X-API-Key", *seen2)
	}
}

// The Δ4b estate walk. It aborts on the first refused hop, so an unauthenticated sweep sees no
// estate at all — "no releases, no work" is indistinguishable from an empty Registry.
func TestRegistryClientSendsAPIKeyOnlyWhenSet(t *testing.T) {
	bodies := map[string]string{
		"/api/v1/products":                 `[{"id":"prod-1"}]`,
		"/api/v1/products/prod-1/projects": `[{"id":"proj-1"}]`,
		"/api/v1/projects/proj-1/releases": `[{"id":"rel-a"}]`,
	}
	srv, seen := authedPeer(t, bodies)
	ids, err := readapi.NewRegistryClient(srv.URL, srv.Client()).WithAPIKey(nodeKey).
		ListReleaseIDs(context.Background())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(ids) != 1 || ids[0] != "rel-a" {
		t.Errorf("ids = %v", ids)
	}
	assertSentKey(t, seen, 3)

	srv2, seen2 := authedPeer(t, bodies)
	_, err = readapi.NewRegistryClient(srv2.URL, srv2.Client()).ListReleaseIDs(context.Background())
	if err == nil {
		t.Fatal("an unauthenticated walk must abort")
	}
	for _, want := range []string{"401", "sent no X-API-Key", "THEMIS_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
	if len(*seen2) != 1 || (*seen2)[0] != "" {
		t.Errorf("headers seen = %q, want one refused request carrying no X-API-Key", *seen2)
	}
	// A refused key names Registry, not Governance — the operator needs to know which peer said no.
	_, err = readapi.NewRegistryClient(srv2.URL, srv2.Client()).WithAPIKey("stale-key").
		ListReleaseIDs(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Registry refused") {
		t.Errorf("err = %v, want it to name the peer that refused", err)
	}
}

// The one WRITE: the autonomous proposal push. Its 403 says the key must be write-capable,
// because a read-scoped key authenticates and is then refused by Governance's write floor —
// the single most confusing outcome of this change if it were not stated.
func TestProposalWriterSaysWhyOnAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := readapi.NewProposalWriter(srv.URL, "", srv.Client()).
		RaiseAIProposal(context.Background(), "F1", "not_affected", "because")
	if err == nil || !strings.Contains(err.Error(), "THEMIS_API_KEY") {
		t.Errorf("err = %v, want the credential hint", err)
	}
	err = readapi.NewProposalWriter(srv.URL, "read-only-key", srv.Client()).
		RaiseAIProposal(context.Background(), "F1", "not_affected", "because")
	if err == nil || !strings.Contains(err.Error(), "Governance refused") {
		t.Errorf("err = %v, want it to distinguish a refused key from an absent one", err)
	}
	if strings.Contains(err.Error(), "read-only-key") {
		t.Errorf("err = %v leaked the credential", err)
	}
}
