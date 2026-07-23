package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// --- fakes ---------------------------------------------------------------------------

type fakeRepo struct {
	byID           map[domain.FindingID]domain.Finding
	order          []domain.FindingID
	saveCalls      int
	conflictFor    int // return ErrConcurrent while saveCalls <= conflictFor
	getByIDErr     error
	getByKeyErr    error
	byFaultlineErr error
	saveErr        error
	lastNotes      []app.OutboxNote
}

func newRepo() *fakeRepo { return &fakeRepo{byID: map[domain.FindingID]domain.Finding{}} }

func (r *fakeRepo) seed(f domain.Finding) {
	if _, ok := r.byID[f.ID()]; !ok {
		r.order = append(r.order, f.ID())
	}
	r.byID[f.ID()] = f
}

func (r *fakeRepo) GetByKey(_ context.Context, rel, fl string) (domain.Finding, bool, error) {
	if r.getByKeyErr != nil {
		return domain.Finding{}, false, r.getByKeyErr
	}
	for _, id := range r.order {
		if f := r.byID[id]; f.ReleaseID() == rel && f.FaultlineID() == fl {
			return clone(f), true, nil
		}
	}
	return domain.Finding{}, false, nil
}

func (r *fakeRepo) GetByID(_ context.Context, id domain.FindingID) (domain.Finding, error) {
	if r.getByIDErr != nil {
		return domain.Finding{}, r.getByIDErr
	}
	f, ok := r.byID[id]
	if !ok {
		return domain.Finding{}, errors.New("not found")
	}
	return clone(f), nil
}

// clone reconstitutes an independent Finding so a returned aggregate never aliases the
// stored one — faithful to the real store, which rebuilds fresh objects on every load.
func clone(f domain.Finding) domain.Finding {
	return domain.ReconstituteFinding(f.ID(), f.ReleaseID(), f.FaultlineID(), f.CVE(),
		f.Components(), f.Stage(), f.Proposals(), f.Positions(), f.Version())
}

func (r *fakeRepo) FindingsByFaultline(_ context.Context, fl string) ([]domain.FindingID, error) {
	if r.byFaultlineErr != nil {
		return nil, r.byFaultlineErr
	}
	var out []domain.FindingID
	for _, id := range r.order {
		if r.byID[id].FaultlineID() == fl {
			out = append(out, id)
		}
	}
	return out, nil
}

func (r *fakeRepo) Save(_ context.Context, f domain.Finding, _ bool, _ int, notes []app.OutboxNote) error {
	r.saveCalls++
	if r.saveErr != nil {
		return r.saveErr
	}
	if r.saveCalls <= r.conflictFor {
		return app.ErrConcurrent
	}
	r.seed(f)
	r.lastNotes = notes
	return nil
}

type seqIDs struct{ n int }

func (g *seqIDs) NewID() string { g.n++; return fmt.Sprintf("id-%d", g.n) }

type emptyIDs struct{}

func (emptyIDs) NewID() string { return "" }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

type zeroClock struct{}

func (zeroClock) Now() time.Time { return time.Time{} }

func writeSvc(r app.Repository, pol ...domain.PolicyRule) *app.FindingService {
	return app.NewFindingService(r, &seqIDs{}, fixedClock{}, pol...)
}

var (
	human = domain.Actor{Kind: domain.ActorHuman, ID: "alice"}
	ai    = domain.Actor{Kind: domain.ActorAI, ID: "analyst"}
)

func comp(purl string) domain.MatchedComponent { return domain.MatchedComponent{PURL: purl} }

func identified(t *testing.T, id, rel, fl, cve string) domain.Finding {
	t.Helper()
	f, err := domain.NewFinding(domain.FindingID(id), rel, fl, cve)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func noteTypes(notes []app.OutboxNote) []string {
	out := make([]string, len(notes))
	for i, n := range notes {
		out[i] = n.EventType
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- OpenOrUpdateFinding (D5) --------------------------------------------------------

func TestOpenOrUpdateFinding_Create(t *testing.T) {
	repo := newRepo()
	id, err := writeSvc(repo).OpenOrUpdateFinding(context.Background(), "rel-1", "fl-1", "CVE-2024-1", []domain.MatchedComponent{comp("pkg:a")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if id == "" {
		t.Fatal("empty finding id")
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventFindingOpened}) {
		t.Errorf("notes = %v, want [finding_opened]", got)
	}
	if got := repo.byID[id]; len(got.Components()) != 1 || got.Stage() != domain.StageIdentified {
		t.Errorf("finding = %+v", got)
	}
}

func TestOpenOrUpdateFinding_AbsorbAndIdempotent(t *testing.T) {
	repo := newRepo()
	s := writeSvc(repo)
	ctx := context.Background()
	id, _ := s.OpenOrUpdateFinding(ctx, "rel-1", "fl-1", "CVE-2024-1", []domain.MatchedComponent{comp("pkg:a")})
	createSaves := repo.saveCalls

	// A new component on the same (release,faultline) is absorbed (no FindingOpened note).
	if _, err := s.OpenOrUpdateFinding(ctx, "rel-1", "fl-1", "CVE-2024-1", []domain.MatchedComponent{comp("pkg:b")}); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != createSaves+1 {
		t.Errorf("expected one more save, got %d", repo.saveCalls)
	}
	if len(noteTypes(repo.lastNotes)) != 0 {
		t.Errorf("absorb must emit no event, got %v", noteTypes(repo.lastNotes))
	}
	if len(repo.byID[id].Components()) != 2 {
		t.Errorf("components = %d, want 2", len(repo.byID[id].Components()))
	}

	// Re-delivery of an already-present component performs no write (idempotent).
	saves := repo.saveCalls
	if _, err := s.OpenOrUpdateFinding(ctx, "rel-1", "fl-1", "CVE-2024-1", []domain.MatchedComponent{comp("pkg:a")}); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != saves {
		t.Error("idempotent re-delivery must not write")
	}
}

func TestOpenOrUpdateFinding_Errors(t *testing.T) {
	ctx := context.Background()
	comps := []domain.MatchedComponent{comp("pkg:a")}

	if _, err := writeSvc(newRepo()).OpenOrUpdateFinding(ctx, "", "fl-1", "CVE-1", comps); !errors.Is(err, app.ErrInvalidMatch) {
		t.Errorf("empty release err = %v, want ErrInvalidMatch", err)
	}
	if _, err := writeSvc(newRepo()).OpenOrUpdateFinding(ctx, "rel-1", " ", "CVE-1", comps); !errors.Is(err, app.ErrInvalidMatch) {
		t.Errorf("blank faultline err = %v", err)
	}
	// Empty id from the generator → NewFinding fails.
	if _, err := app.NewFindingService(newRepo(), emptyIDs{}, fixedClock{}).OpenOrUpdateFinding(ctx, "rel-1", "fl-1", "CVE-1", comps); err == nil {
		t.Error("empty id: expected NewFinding error")
	}
	// Invalid component (empty PURL) on the create path.
	if _, err := writeSvc(newRepo()).OpenOrUpdateFinding(ctx, "rel-1", "fl-1", "CVE-1", []domain.MatchedComponent{{Name: "x"}}); err == nil {
		t.Error("empty PURL: expected error")
	}
	// GetByKey error.
	ge := newRepo()
	ge.getByKeyErr = errors.New("db down")
	if _, err := writeSvc(ge).OpenOrUpdateFinding(ctx, "rel-1", "fl-1", "CVE-1", comps); err == nil {
		t.Error("get error: expected error")
	}
	// Non-concurrent save error.
	se := newRepo()
	se.saveErr = errors.New("write failed")
	if _, err := writeSvc(se).OpenOrUpdateFinding(ctx, "rel-1", "fl-1", "CVE-1", comps); err == nil {
		t.Error("save error: expected error")
	}
}

func TestOpenOrUpdateFinding_ConcurrencyRetry(t *testing.T) {
	repo := newRepo()
	repo.conflictFor = 2 // first two saves conflict, third wins
	id, err := writeSvc(repo).OpenOrUpdateFinding(context.Background(), "rel-1", "fl-1", "CVE-1", []domain.MatchedComponent{comp("pkg:a")})
	if err != nil || id == "" || repo.saveCalls != 3 {
		t.Errorf("expected convergence after 3 saves: id=%q saves=%d err=%v", id, repo.saveCalls, err)
	}
	// Exhausted retries → ErrConcurrent.
	ce := newRepo()
	ce.conflictFor = 99
	if _, err := writeSvc(ce).OpenOrUpdateFinding(context.Background(), "rel-1", "fl-1", "CVE-1", []domain.MatchedComponent{comp("pkg:a")}); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("exhausted err = %v, want ErrConcurrent", err)
	}
}

// --- ReactToEnrichment (D6) ----------------------------------------------------------

func TestReactToEnrichment_RaisesProposalNoAutoDecide(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo) // no policies → never auto-accept

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{FaultlineID: "fl-1", KEV: true}); err != nil {
		t.Fatalf("react: %v", err)
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventProposalRaised}) {
		t.Errorf("notes = %v, want [proposal_raised]", got)
	}
	f := repo.byID["fnd-1"]
	if f.Stage() != domain.StageUnderInvestigation {
		t.Errorf("stage = %q, want under_investigation (flagged for review)", f.Stage())
	}
	if _, ok := f.CurrentPosition(); ok {
		t.Error("enrichment must never auto-establish a Position")
	}
	// The raised proposal proposes Affected (KEV → re-prioritize) by a system proposer.
	p := f.Proposals()[0]
	if p.Stance() != domain.StanceAffected || p.Proposer().Kind != domain.ActorSystem {
		t.Errorf("proposal = %+v", p)
	}
}

func TestReactToEnrichment_Idempotent(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo)
	ctx := context.Background()
	sig := app.EnrichmentSignal{FaultlineID: "fl-1", HighSeverity: true}

	if err := s.ReactToEnrichment(ctx, sig); err != nil {
		t.Fatal(err)
	}
	saves := repo.saveCalls
	// Re-delivery of the same signal raises no duplicate proposal and performs no write.
	if err := s.ReactToEnrichment(ctx, sig); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != saves {
		t.Errorf("re-delivery wrote (%d → %d); want idempotent", saves, repo.saveCalls)
	}
	if n := len(repo.byID["fnd-1"].Proposals()); n != 1 {
		t.Errorf("proposals = %d, want 1", n)
	}
}

func TestReactToEnrichment_PolicyAutoAccept(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	policy := domain.NewPolicyRule("auto-not-affected", domain.StanceNotAffected)
	s := writeSvc(repo, policy)

	// Withdrawn → system proposes Not-Affected → policy auto-accepts → Position established.
	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{FaultlineID: "fl-1", Withdrawn: true}); err != nil {
		t.Fatalf("react: %v", err)
	}
	want := []string{app.EventProposalRaised, app.EventProposalAccepted, app.EventPositionEstablished}
	if got := noteTypes(repo.lastNotes); !eq(got, want) {
		t.Errorf("notes = %v, want %v", got, want)
	}
	f := repo.byID["fnd-1"]
	pos, ok := f.CurrentPosition()
	if !ok || pos.Stance() != domain.StanceNotAffected || pos.Actor().Kind != domain.ActorPolicy {
		t.Errorf("auto-accepted position = %+v ok=%v", pos, ok)
	}
	if f.Stage() != domain.StagePositionEstablished {
		t.Errorf("stage = %q", f.Stage())
	}
}

func TestReactToEnrichment_NoDecisionImpactAndErrors(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo)

	// Minor change (no KEV/high-sev/withdrawn) → advisory only, no proposal, no write.
	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{FaultlineID: "fl-1"}); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != 0 {
		t.Error("no-decision-impact enrichment must not write")
	}

	// FindingsByFaultline error propagates.
	fe := newRepo()
	fe.byFaultlineErr = errors.New("db down")
	if err := writeSvc(fe).ReactToEnrichment(context.Background(), app.EnrichmentSignal{FaultlineID: "fl-1", KEV: true}); err == nil {
		t.Error("byFaultline error: expected error")
	}
}

// --- RaiseProposal / Accept / Reject (D4/D11) ---------------------------------------

func TestRaiseProposal_Human(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo, domain.NewPolicyRule("auto-na", domain.StanceNotAffected))

	// A human proposal is never auto-accepted, even for a policy-covered stance.
	pid, err := s.RaiseProposal(context.Background(), "fnd-1", human, domain.StanceNotAffected, "manual review")
	if err != nil || pid == "" {
		t.Fatalf("raise: pid=%q err=%v", pid, err)
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventProposalRaised}) {
		t.Errorf("notes = %v, want [proposal_raised]", got)
	}
	if _, ok := repo.byID["fnd-1"].CurrentPosition(); ok {
		t.Error("human proposal must not auto-establish a Position")
	}

	// Unknown finding → error.
	if _, err := s.RaiseProposal(context.Background(), "nope", human, domain.StanceAffected, ""); err == nil {
		t.Error("unknown finding: expected error")
	}
}

func TestAcceptProposal(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo)
	ctx := context.Background()

	pid, _ := s.RaiseProposal(ctx, "fnd-1", human, domain.StanceAffected, "confirmed")

	// AI may not decide.
	if err := s.AcceptProposal(ctx, "fnd-1", pid, ai); !errors.Is(err, app.ErrUnauthorized) {
		t.Errorf("AI accept err = %v, want ErrUnauthorized", err)
	}
	// Human accepts → Position established.
	if err := s.AcceptProposal(ctx, "fnd-1", pid, human); err != nil {
		t.Fatalf("accept: %v", err)
	}
	want := []string{app.EventProposalAccepted, app.EventPositionEstablished}
	if got := noteTypes(repo.lastNotes); !eq(got, want) {
		t.Errorf("notes = %v, want %v", got, want)
	}
	f := repo.byID["fnd-1"]
	if pos, ok := f.CurrentPosition(); !ok || pos.Version() != 1 || pos.Stance() != domain.StanceAffected {
		t.Errorf("position = %+v ok=%v", pos, ok)
	}
	if f.Stage() != domain.StagePositionEstablished {
		t.Errorf("stage = %q", f.Stage())
	}

	// Accepting an unknown proposal surfaces the domain error (not swallowed as no-op).
	if err := s.AcceptProposal(ctx, "fnd-1", "ghost", human); !errors.Is(err, domain.ErrProposalNotFound) {
		t.Errorf("unknown proposal err = %v", err)
	}
}

func TestAcceptProposal_RevisionEmitsRevised(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo)
	ctx := context.Background()

	// v1.
	pid1, _ := s.RaiseProposal(ctx, "fnd-1", human, domain.StanceAffected, "confirmed")
	if err := s.AcceptProposal(ctx, "fnd-1", pid1, human); err != nil {
		t.Fatal(err)
	}
	// v2 → PositionRevised.
	pid2, _ := s.RaiseProposal(ctx, "fnd-1", human, domain.StanceMitigated, "fixed")
	if err := s.AcceptProposal(ctx, "fnd-1", pid2, human); err != nil {
		t.Fatal(err)
	}
	want := []string{app.EventProposalAccepted, app.EventPositionRevised}
	if got := noteTypes(repo.lastNotes); !eq(got, want) {
		t.Errorf("notes = %v, want %v", got, want)
	}
	if pos, _ := repo.byID["fnd-1"].CurrentPosition(); pos.Version() != 2 {
		t.Errorf("current version = %d, want 2", pos.Version())
	}
}

func TestRaiseProposal_OnArchivedFails(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	_ = f.Archive()
	repo.seed(f)
	if _, err := writeSvc(repo).RaiseProposal(context.Background(), "fnd-1", human, domain.StanceAffected, "x"); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("raise on archived err = %v, want ErrIllegalTransition", err)
	}
}

func TestWriteService_MisconfiguredClockAndPolicy(t *testing.T) {
	ctx := context.Background()

	// A zero clock makes proposal construction fail — surfaced, not swallowed.
	zc := newRepo()
	zc.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	badClock := app.NewFindingService(zc, &seqIDs{}, zeroClock{})
	if _, err := badClock.RaiseProposal(ctx, "fnd-1", human, domain.StanceAffected, "x"); err == nil {
		t.Error("zero-clock RaiseProposal: expected error")
	}
	if err := badClock.ReactToEnrichment(ctx, app.EnrichmentSignal{FaultlineID: "fl-1", KEV: true}); err == nil {
		t.Error("zero-clock ReactToEnrichment: expected error")
	}

	// A policy with no name matches but yields an un-attributable (empty-id) decider, so
	// the auto-accept fails safely rather than establishing an unrecorded Position.
	np := newRepo()
	np.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	svc := app.NewFindingService(np, &seqIDs{}, fixedClock{}, domain.NewPolicyRule("", domain.StanceNotAffected))
	if err := svc.ReactToEnrichment(ctx, app.EnrichmentSignal{FaultlineID: "fl-1", Withdrawn: true}); err == nil {
		t.Error("nameless-policy auto-accept: expected error")
	}
}

func TestReactToEnrichment_SaveErrorPropagates(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	repo.saveErr = errors.New("write failed")
	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{FaultlineID: "fl-1", KEV: true}); err == nil {
		t.Error("enrichment save error: expected error")
	}
}

func TestAcceptProposal_ConcurrencyExhausted(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	// Seed an open proposal directly so accept has a target.
	f := repo.byID["fnd-1"]
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAffected, "x", fixedClock{}.Now())
	_ = f.RaiseProposal(p)
	repo.seed(f)
	repo.conflictFor = 99

	if err := writeSvc(repo).AcceptProposal(context.Background(), "fnd-1", "p1", human); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("exhausted accept err = %v, want ErrConcurrent", err)
	}
}

func TestRejectProposal(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo)
	ctx := context.Background()
	pid, _ := s.RaiseProposal(ctx, "fnd-1", human, domain.StanceNotAffected, "vendor VEX")

	// AI may not reject.
	if err := s.RejectProposal(ctx, "fnd-1", pid, ai); !errors.Is(err, app.ErrUnauthorized) {
		t.Errorf("AI reject err = %v", err)
	}
	if err := s.RejectProposal(ctx, "fnd-1", pid, human); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventProposalRejected}) {
		t.Errorf("notes = %v, want [proposal_rejected]", got)
	}
	if repo.byID["fnd-1"].Proposals()[0].Status() != domain.StatusRejected {
		t.Error("proposal should be rejected")
	}

	// Rejecting an unknown proposal surfaces the domain error.
	if err := s.RejectProposal(ctx, "fnd-1", "ghost", human); !errors.Is(err, domain.ErrProposalNotFound) {
		t.Errorf("unknown reject err = %v, want ErrProposalNotFound", err)
	}
}

// --- Lifecycle ops (D7) --------------------------------------------------------------

func TestLifecycleOps(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo)
	ctx := context.Background()

	if err := s.ResolveFinding(ctx, "fnd-1"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventFindingResolved}) {
		t.Errorf("notes = %v", got)
	}
	// Idempotent re-resolve: no event, no write.
	saves := repo.saveCalls
	if err := s.ResolveFinding(ctx, "fnd-1"); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != saves {
		t.Error("re-resolve must not write")
	}

	// Reopen from Resolved.
	if err := s.ReopenFinding(ctx, "fnd-1"); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventFindingReopened}) {
		t.Errorf("reopen notes = %v", got)
	}
	// Reopen from Under Investigation is illegal → domain error surfaces.
	if err := s.ReopenFinding(ctx, "fnd-1"); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("illegal reopen err = %v", err)
	}

	// Archive → terminal; re-archive is a no-op.
	if err := s.ArchiveFinding(ctx, "fnd-1"); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventFindingArchived}) {
		t.Errorf("archive notes = %v", got)
	}
	saves = repo.saveCalls
	if err := s.ArchiveFinding(ctx, "fnd-1"); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != saves {
		t.Error("re-archive must not write")
	}
}

func TestLifecycleOps_RepoErrors(t *testing.T) {
	// GetByID error.
	ge := newRepo()
	ge.getByIDErr = errors.New("db down")
	if err := writeSvc(ge).ResolveFinding(context.Background(), "fnd-1"); err == nil {
		t.Error("get error: expected error")
	}
	// Save error.
	se := newRepo()
	se.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	se.saveErr = errors.New("write failed")
	if err := writeSvc(se).ResolveFinding(context.Background(), "fnd-1"); err == nil {
		t.Error("save error: expected error")
	}
}
