package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// --- fakes -----------------------------------------------------------------------------

type fakeRepo struct {
	byID  map[domain.FindingID]domain.Finding
	order []domain.FindingID
	err   error
}

func newRepo() *fakeRepo { return &fakeRepo{byID: map[domain.FindingID]domain.Finding{}} }

func (r *fakeRepo) seed(f domain.Finding) {
	if _, ok := r.byID[f.ID()]; !ok {
		r.order = append(r.order, f.ID())
	}
	r.byID[f.ID()] = f
}

func clone(f domain.Finding) domain.Finding {
	return domain.ReconstituteFinding(f.ID(), f.ReleaseID(), f.FaultlineID(), f.CVE(),
		f.Components(), f.Stage(), f.Proposals(), f.Positions(), f.Version())
}

func (r *fakeRepo) GetByKey(_ context.Context, rel, fl string) (domain.Finding, bool, error) {
	if r.err != nil {
		return domain.Finding{}, false, r.err
	}
	for _, id := range r.order {
		if f := r.byID[id]; f.ReleaseID() == rel && f.FaultlineID() == fl {
			return clone(f), true, nil
		}
	}
	return domain.Finding{}, false, nil
}

func (r *fakeRepo) GetByID(_ context.Context, id domain.FindingID) (domain.Finding, error) {
	if r.err != nil {
		return domain.Finding{}, r.err
	}
	f, ok := r.byID[id]
	if !ok {
		return domain.Finding{}, store.ErrNotFound
	}
	return clone(f), nil
}

func (r *fakeRepo) FindingsByFaultline(_ context.Context, fl string) ([]domain.FindingID, error) {
	var out []domain.FindingID
	for _, id := range r.order {
		if r.byID[id].FaultlineID() == fl {
			out = append(out, id)
		}
	}
	return out, nil
}

func (r *fakeRepo) Save(_ context.Context, f domain.Finding, _ bool, _ int, _ []app.OutboxNote) error {
	if r.err != nil {
		return r.err
	}
	r.seed(f)
	return nil
}

type fakeProjection struct {
	posture []app.PostureEntry
	blast   []string
	err     error
}

func (p fakeProjection) ReleasePosture(context.Context, string) ([]app.PostureEntry, error) {
	return p.posture, p.err
}

func (p fakeProjection) FaultlineBlastRadius(context.Context, string) ([]string, error) {
	return p.blast, p.err
}

type seqIDs struct{ n int }

func (g *seqIDs) NewID() string { g.n++; return fmt.Sprintf("id-%d", g.n) }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

var human = domain.Actor{Kind: domain.ActorHuman, ID: "alice"}

func server(t *testing.T, repo *fakeRepo, proj fakeProjection) *httptest.Server {
	t.Helper()
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	read := app.NewReadService(repo, proj)
	srv := httptest.NewServer(govhttp.NewHandler(write, read).Router())
	t.Cleanup(srv.Close)
	return srv
}

func identified(t *testing.T, id, rel, fl, cve string) domain.Finding {
	t.Helper()
	f, err := domain.NewFinding(domain.FindingID(id), rel, fl, cve)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func do(t *testing.T, method, url string, body any) (int, []byte) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf [8192]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, buf[:n]
}

// --- reads -----------------------------------------------------------------------------

func TestGetFinding(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	_, _ = f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:a"})
	// A raised + accepted proposal exercises the proposal + position + current-position mappers.
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAffected, "confirmed", fixedClock{}.Now())
	_ = f.RaiseProposal(p)
	_, _ = f.AcceptProposal("p1", human, fixedClock{}.Now())
	repo.seed(f)
	srv := server(t, repo, fakeProjection{})

	status, body := do(t, http.MethodGet, srv.URL+"/findings/fnd-1", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var v struct {
		Id              string           `json:"id"`
		ReleaseId       string           `json:"release_id"`
		Stage           string           `json:"stage"`
		Components      []map[string]any `json:"components"`
		Proposals       []map[string]any `json:"proposals"`
		Positions       []map[string]any `json:"positions"`
		CurrentPosition map[string]any   `json:"current_position"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.Id != "fnd-1" || v.ReleaseId != "rel-1" || v.Stage != "position_established" || len(v.Components) != 1 {
		t.Errorf("view = %+v", v)
	}
	if len(v.Proposals) != 1 || len(v.Positions) != 1 || v.CurrentPosition == nil {
		t.Errorf("proposals/positions/current = %d/%d/%v", len(v.Proposals), len(v.Positions), v.CurrentPosition)
	}

	// Unknown → 404.
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/nope", nil); status != http.StatusNotFound {
		t.Errorf("unknown finding status = %d, want 404", status)
	}

	// Repo error → 500 (writeErr default branch).
	bad := newRepo()
	bad.err = errors.New("db down")
	badSrv := server(t, bad, fakeProjection{})
	if status, _ := do(t, http.MethodGet, badSrv.URL+"/findings/fnd-1", nil); status != http.StatusInternalServerError {
		t.Errorf("repo-error status = %d, want 500", status)
	}
}

func TestGetFindingByKey(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	srv := server(t, repo, fakeProjection{})

	if status, _ := do(t, http.MethodGet, srv.URL+"/findings?release=rel-1&faultline=fl-1", nil); status != http.StatusOK {
		t.Errorf("by key status = %d, want 200", status)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings?release=x&faultline=y", nil); status != http.StatusNotFound {
		t.Errorf("unknown key status = %d, want 404", status)
	}

	// Repo error → 500.
	bad := newRepo()
	bad.err = errors.New("db down")
	badSrv := server(t, bad, fakeProjection{})
	if status, _ := do(t, http.MethodGet, badSrv.URL+"/findings?release=r&faultline=f", nil); status != http.StatusInternalServerError {
		t.Errorf("error status = %d, want 500", status)
	}
}

func TestGetPosition(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAffected, "x", fixedClock{}.Now())
	_ = f.RaiseProposal(p)
	_, _ = f.AcceptProposal("p1", human, fixedClock{}.Now())
	repo.seed(f)
	srv := server(t, repo, fakeProjection{})

	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/fnd-1/position", nil); status != http.StatusOK {
		t.Errorf("latest position status = %d, want 200", status)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/fnd-1/position?version=1", nil); status != http.StatusOK {
		t.Errorf("v1 status = %d, want 200", status)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/fnd-1/position?version=9", nil); status != http.StatusNotFound {
		t.Errorf("unknown version status = %d, want 404", status)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/ghost/position", nil); status != http.StatusNotFound {
		t.Errorf("unknown finding status = %d, want 404", status)
	}
}

func TestPostureAndBlastRadius(t *testing.T) {
	proj := fakeProjection{
		posture: []app.PostureEntry{{FindingID: "fnd-1", Stage: domain.StagePositionEstablished, Stance: domain.StanceAffected, HasPosition: true}},
		blast:   []string{"rel-1", "rel-2"},
	}
	srv := server(t, newRepo(), proj)

	status, body := do(t, http.MethodGet, srv.URL+"/releases/rel-1/posture", nil)
	if status != http.StatusOK {
		t.Fatalf("posture status = %d", status)
	}
	var entries []map[string]any
	if err := json.Unmarshal(body, &entries); err != nil || len(entries) != 1 {
		t.Errorf("posture = %v err=%v", entries, err)
	}

	status, body = do(t, http.MethodGet, srv.URL+"/faultlines/fl-1/blast-radius", nil)
	if status != http.StatusOK {
		t.Fatalf("blast status = %d", status)
	}
	var rels []string
	if err := json.Unmarshal(body, &rels); err != nil || len(rels) != 2 {
		t.Errorf("blast = %v err=%v", rels, err)
	}

	// Projection errors → 500.
	bad := server(t, newRepo(), fakeProjection{err: errors.New("proj down")})
	if status, _ := do(t, http.MethodGet, bad.URL+"/releases/rel-1/posture", nil); status != http.StatusInternalServerError {
		t.Errorf("posture error status = %d, want 500", status)
	}
	if status, _ := do(t, http.MethodGet, bad.URL+"/faultlines/fl-1/blast-radius", nil); status != http.StatusInternalServerError {
		t.Errorf("blast error status = %d, want 500", status)
	}
}

// --- writes ----------------------------------------------------------------------------

func TestRaiseProposal(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	srv := server(t, repo, fakeProjection{})

	status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals",
		map[string]any{"stance": "affected", "rationale": "confirmed"})
	if status != http.StatusCreated {
		t.Fatalf("status = %d: %s", status, body)
	}
	var out struct {
		ProposalId string `json:"proposal_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.ProposalId == "" {
		t.Errorf("response = %s err=%v", body, err)
	}

	// An AI proposer with an explicit id (covers the ai + proposer_id mapping branches).
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals",
		map[string]any{"stance": "not_affected", "proposer_kind": "ai", "proposer_id": "triage-bot"}); status != http.StatusCreated {
		t.Errorf("ai proposer status = %d, want 201", status)
	}
	// Invalid stance → 400.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals", map[string]any{"stance": "bogus"}); status != http.StatusBadRequest {
		t.Errorf("bad stance status = %d, want 400", status)
	}
	// Invalid proposer kind → 400.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals", map[string]any{"stance": "affected", "proposer_kind": "system"}); status != http.StatusBadRequest {
		t.Errorf("bad proposer status = %d, want 400", status)
	}
	// Malformed body → 400.
	if status, _ := doRaw(t, srv.URL+"/findings/fnd-1/proposals", "{not json"); status != http.StatusBadRequest {
		t.Errorf("malformed body status = %d, want 400", status)
	}
	// Unknown finding → 404.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/ghost/proposals", map[string]any{"stance": "affected"}); status != http.StatusNotFound {
		t.Errorf("unknown finding status = %d, want 404", status)
	}
}

func TestAcceptAndRejectProposal(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAffected, "x", fixedClock{}.Now())
	_ = f.RaiseProposal(p)
	repo.seed(f)
	srv := server(t, repo, fakeProjection{})
	base := srv.URL + "/findings/fnd-1/proposals/p1"

	// Missing actor_id → 400.
	if status, _ := do(t, http.MethodPost, base+"/accept", map[string]any{}); status != http.StatusBadRequest {
		t.Errorf("missing actor status = %d, want 400", status)
	}
	// AI decider → app refuses → 403.
	if status, _ := do(t, http.MethodPost, base+"/accept", map[string]any{"actor_id": "bot", "actor_kind": "ai"}); status != http.StatusForbidden {
		t.Errorf("ai decider status = %d, want 403", status)
	}
	// Unsupported decider kind → 400.
	if status, _ := do(t, http.MethodPost, base+"/accept", map[string]any{"actor_id": "x", "actor_kind": "wizard"}); status != http.StatusBadRequest {
		t.Errorf("bad kind status = %d, want 400", status)
	}
	// Human accepts (explicit kind, covers the human switch branch) → 204.
	if status, _ := do(t, http.MethodPost, base+"/accept", map[string]any{"actor_id": "alice", "actor_kind": "human"}); status != http.StatusNoContent {
		t.Errorf("accept status = %d, want 204", status)
	}
	// Re-accept the now-decided proposal → 409.
	if status, _ := do(t, http.MethodPost, base+"/accept", map[string]any{"actor_id": "alice"}); status != http.StatusConflict {
		t.Errorf("re-accept status = %d, want 409", status)
	}
}

func TestRejectProposal(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceNotAffected, "vendor VEX", fixedClock{}.Now())
	_ = f.RaiseProposal(p)
	repo.seed(f)
	srv := server(t, repo, fakeProjection{})

	// Happy reject → 204.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals/p1/reject", map[string]any{"actor_id": "alice"}); status != http.StatusNoContent {
		t.Errorf("reject status = %d, want 204", status)
	}
	// Rejecting an absent proposal → 404.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals/ghost/reject", map[string]any{"actor_id": "alice"}); status != http.StatusNotFound {
		t.Errorf("reject unknown status = %d, want 404", status)
	}
}

func TestLifecycleEndpoints(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	srv := server(t, repo, fakeProjection{})

	// Resolve → 204.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/resolve", nil); status != http.StatusNoContent {
		t.Errorf("resolve status = %d, want 204", status)
	}
	// Reopen → 204.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/reopen", nil); status != http.StatusNoContent {
		t.Errorf("reopen status = %d, want 204", status)
	}
	// Reopen again (from Under Investigation) is illegal → 409.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/reopen", nil); status != http.StatusConflict {
		t.Errorf("illegal reopen status = %d, want 409", status)
	}
	// Archive → 204; unknown finding → 404.
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/archive", nil); status != http.StatusNoContent {
		t.Errorf("archive status = %d, want 204", status)
	}
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/ghost/resolve", nil); status != http.StatusNotFound {
		t.Errorf("unknown resolve status = %d, want 404", status)
	}
	if status, _ := do(t, http.MethodPost, srv.URL+"/findings/ghost/archive", nil); status != http.StatusNotFound {
		t.Errorf("unknown archive status = %d, want 404", status)
	}
}

func TestBlastRadiusEmpty(t *testing.T) {
	// A Faultline with no matches returns an empty (non-null) array.
	srv := server(t, newRepo(), fakeProjection{})
	status, body := do(t, http.MethodGet, srv.URL+"/faultlines/fl-x/blast-radius", nil)
	if status != http.StatusOK || string(body) != "[]\n" {
		t.Errorf("empty blast = %q status=%d", body, status)
	}
}

func doRaw(t *testing.T, url, raw string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader([]byte(raw)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf [4096]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, buf[:n]
}
