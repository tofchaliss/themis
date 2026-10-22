package http_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// EDR-REMEDIATION-01 D2 at the edge: a person's accepted_risk without an owner is a 400 that
// decides nothing; with one, the owner, treatment, proof and review date come back on the
// Position; terms on a stance that carries no acceptance are a 400.
func TestAcceptProposal_RiskAcceptanceTerms(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAcceptedRisk, "compensating control", fixedClock{}.Now(), value.TrustAsserted)
	_ = f.RaiseProposal(p)
	repo.seed(f)
	g := identified(t, "fnd-2", "rel-1", "fl-2", "CVE-2")
	q, _ := domain.NewGovernanceProposal("p1", human, domain.StanceNotAffected, "x", fixedClock{}.Now(), value.TrustAsserted)
	_ = g.RaiseProposal(q)
	repo.seed(g)
	srv := server(t, repo, fakeProjection{})
	accept := srv.URL + "/findings/fnd-1/proposals/p1/accept"

	if status, body := do(t, http.MethodPost, accept, map[string]any{"actor_id": "alice"}); status != http.StatusBadRequest {
		t.Fatalf("no owner = %d %s, want 400", status, body)
	}
	if status, _ := do(t, http.MethodPost, accept, map[string]any{"actor_id": "alice", "owner": "bob", "treatment": "ignore"}); status != http.StatusBadRequest {
		t.Fatalf("bad treatment = %d, want 400", status)
	}
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-2/proposals/p1/accept", map[string]any{"actor_id": "alice", "owner": "bob"}); status != http.StatusBadRequest {
		t.Fatalf("owner on not_affected = %d, want 400", status)
	}
	if status, body := do(t, http.MethodPost, accept, map[string]any{
		"actor_id": "alice", "owner": "bob@example.test", "treatment": "mitigate_later",
		"proof": "https://wiki.example.test/risk/7", "review_by": "2027-01-15T00:00:00Z",
	}); status != http.StatusNoContent {
		t.Fatalf("accept = %d %s, want 204", status, body)
	}
	status, body := do(t, http.MethodGet, srv.URL+"/findings/fnd-1/position", nil)
	var v gen.PositionView
	if status != http.StatusOK || json.Unmarshal(body, &v) != nil {
		t.Fatalf("position = %d %s", status, body)
	}
	if v.Owner == nil || *v.Owner != "bob@example.test" || v.Treatment == nil || *v.Treatment != "mitigate_later" ||
		v.Proof == nil || v.ReviewBy == nil || v.ReviewBy.Year() != 2027 {
		t.Fatalf("view = %s", body)
	}
}
