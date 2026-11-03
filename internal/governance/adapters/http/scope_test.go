package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// stubOwners is the Registry identity seam: release → (product, project).
type stubOwners struct {
	owners map[string][2]string
	err    error
}

func (s stubOwners) ProductAndProjectOfRelease(_ context.Context, rel string) (string, string, error) {
	if s.err != nil {
		return "", "", s.err
	}
	o := s.owners[rel]
	return o[0], o[1], nil
}

// stubUndecided answers UndecidedFindingsByRelease from the repo.
type stubUndecided struct{ repo *fakeRepo }

func (s stubUndecided) UndecidedFindingsByRelease(_ context.Context, rel string) ([]domain.FindingID, error) {
	var out []domain.FindingID
	for _, id := range s.repo.order {
		if f := s.repo.byID[id]; f.ReleaseID() == rel {
			if _, decided := f.CurrentPosition(); !decided {
				out = append(out, id)
			}
		}
	}
	return out, nil
}

type noPending struct{}

func (noPending) PendingScopedPositions(context.Context, int) ([]app.ScopedPosition, error) {
	return nil, nil
}
func (noPending) MarkScopeApplied(context.Context, domain.FindingID, int) error { return nil }

func withPURL(t *testing.T, f domain.Finding, purl string) domain.Finding {
	t.Helper()
	if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: purl, Name: "libtiff", Version: "1", ClaimClass: "carrier"}); err != nil {
		t.Fatal(err)
	}
	return f
}

// The decision carries its scope (EDR-SYNC-01 D1): accepted with scope product, the Position
// view says so; an unknown scope is refused with 400 before anything is written; a propagated
// Position names its source on the wire.
func TestAcceptProposal_Scope(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceNotAffected, "x", fixedClock{}.Now(), value.TrustAsserted)
	_ = f.RaiseProposal(p)
	repo.seed(f)
	srv := server(t, repo, fakeProjection{})

	if status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals/p1/accept",
		map[string]any{"actor_id": "alice", "scope": "estate"}); status != http.StatusBadRequest {
		t.Fatalf("bad scope status = %d: %s", status, body)
	}
	if _, decided := repo.byID["fnd-1"].CurrentPosition(); decided {
		t.Fatal("a refused scope established a Position")
	}
	if status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals/p1/accept",
		map[string]any{"actor_id": "alice", "scope": "product"}); status != http.StatusNoContent {
		t.Fatalf("accept status = %d: %s", status, body)
	}
	status, body := do(t, http.MethodGet, srv.URL+"/findings/fnd-1/position", nil)
	if status != http.StatusOK {
		t.Fatalf("position status = %d", status)
	}
	var view map[string]any
	_ = json.Unmarshal(body, &view)
	if view["scope"] != "product" || view["propagated_from_finding_id"] != nil {
		t.Errorf("position view = %v", view)
	}
	// A pre-record Position reads as release-scoped; a propagated one names its source.
	g := identified(t, "fnd-2", "rel-2", "fl-1", "CVE-1")
	q, _ := domain.NewGovernanceProposal(domain.ScopedProposalID("fnd-2", "fnd-1", 1), human, domain.StanceNotAffected, "x", fixedClock{}.Now(), value.TrustAsserted)
	_ = g.RaiseProposal(q)
	if _, err := g.AcceptProposalWith(q.ID(), human, fixedClock{}.Now(), domain.AcceptanceTerms{Scope: domain.ScopeProduct, PropagatedFrom: domain.PropagationSource{FindingID: "fnd-1", Version: 1}}); err != nil {
		t.Fatal(err)
	}
	repo.seed(g)
	_, body = do(t, http.MethodGet, srv.URL+"/findings/fnd-2/position", nil)
	_ = json.Unmarshal(body, &view)
	if view["scope"] != "product" || view["propagated_from_finding_id"] != "fnd-1" || view["propagated_from_version"] != float64(1) {
		t.Errorf("propagated view = %v", view)
	}
	h := identified(t, "fnd-3", "rel-3", "fl-1", "CVE-1")
	_ = h.RaiseProposal(p)
	_, _ = h.AcceptProposal("p1", human, fixedClock{}.Now())
	repo.seed(h)
	_, body = do(t, http.MethodGet, srv.URL+"/findings/fnd-3/position", nil)
	_ = json.Unmarshal(body, &view)
	if view["scope"] != "release" {
		t.Errorf("pre-record view = %v", view)
	}
}

// The preview (D7): who a scoped decision reaches now, with the project count; 400 on a bad
// scope, 404 on an unknown Finding, 503 with no Registry seam, 500 when Registry fails.
func TestGetScopeTargets(t *testing.T) {
	repo := newRepo()
	repo.seed(withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-1"), "pkg:rpm/rocky/libtiff@1"))
	repo.seed(withPURL(t, identified(t, "a2", "rel-a2", "fl-1", "CVE-1"), "pkg:rpm/rocky/libtiff@2"))
	repo.seed(withPURL(t, identified(t, "b1", "rel-b1", "fl-1", "CVE-1"), "pkg:rpm/rocky/libtiff@1"))
	repo.seed(withPURL(t, identified(t, "c1", "rel-c1", "fl-1", "CVE-1"), "pkg:rpm/rocky/libtiff@1"))
	owners := stubOwners{owners: map[string][2]string{"rel-a1": {"MRF", "A"}, "rel-a2": {"MRF", "A"}, "rel-b1": {"MRF", "B"}, "rel-c1": {"OTHER", "C"}}}
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	read := app.NewReadService(repo, fakeProjection{}, nil, 0)
	newSrv := func(sp *app.ScopePropagation) *httptest.Server {
		h := govhttp.NewHandler(write, read)
		if sp != nil {
			h = h.WithScopePropagation(sp)
		}
		srv := httptest.NewServer(h.Router())
		t.Cleanup(srv.Close)
		return srv
	}
	srv := newSrv(app.NewScopePropagation(write, noPending{}, stubUndecided{repo}, owners))

	status, body := do(t, http.MethodGet, srv.URL+"/findings/src/scope-targets?scope=product", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var view struct {
		FindingID string `json:"finding_id"`
		Scope     string `json:"scope"`
		Count     int    `json:"count"`
		Projects  int    `json:"projects"`
		Targets   []struct {
			FindingID, ReleaseID, ProductID, ProjectID, Level string
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if view.FindingID != "src" || view.Scope != "product" || view.Count != 2 || view.Projects != 2 || len(view.Targets) != 2 {
		t.Fatalf("view = %+v", view)
	}
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)
	tg := raw["targets"].([]any)[0].(map[string]any)
	if tg["finding_id"] != "a2" || tg["level"] != "component" || tg["project_id"] != "A" || tg["product_id"] != "MRF" || tg["release_id"] != "rel-a2" {
		t.Errorf("target = %v", tg)
	}
	if status, body := do(t, http.MethodGet, srv.URL+"/findings/src/scope-targets?scope=release", nil); status != http.StatusOK || !json.Valid(body) {
		t.Errorf("release scope = %d %s", status, body)
	} else {
		_ = json.Unmarshal(body, &view)
		if view.Count != 0 || len(view.Targets) != 0 {
			t.Errorf("release scope reaches %+v", view)
		}
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/src/scope-targets?scope=estate", nil); status != http.StatusBadRequest {
		t.Errorf("bad scope status = %d", status)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/src/scope-targets", nil); status != http.StatusBadRequest {
		t.Errorf("missing scope status = %d", status)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/ghost/scope-targets?scope=product", nil); status != http.StatusNotFound {
		t.Errorf("unknown finding status = %d, want 404", status)
	}
	down := newSrv(app.NewScopePropagation(write, noPending{}, stubUndecided{repo}, stubOwners{err: errors.New("registry down")}))
	if status, _ := do(t, http.MethodGet, down.URL+"/findings/src/scope-targets?scope=product", nil); status != http.StatusInternalServerError {
		t.Errorf("registry outage status = %d, want 500 (never an empty list)", status)
	}
	bare := newSrv(nil)
	if status, _ := do(t, http.MethodGet, bare.URL+"/findings/src/scope-targets?scope=product", nil); status != http.StatusServiceUnavailable {
		t.Errorf("no seam status = %d, want 503", status)
	}
}
