package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

var (
	human  = domain.Actor{Kind: domain.ActorHuman, ID: "alice"}
	system = domain.Actor{Kind: domain.ActorSystem, ID: "faultline-enriched"}
)

func newFinding(t *testing.T) domain.Finding {
	t.Helper()
	f, err := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func proposal(t *testing.T, id domain.ProposalID, proposer domain.Actor, stance domain.Stance) domain.GovernanceProposal {
	t.Helper()
	p, err := domain.NewGovernanceProposal(id, proposer, stance, "because", epoch)
	if err != nil {
		t.Fatalf("NewGovernanceProposal(%s): %v", id, err)
	}
	return p
}

func TestNewFinding(t *testing.T) {
	f := newFinding(t)
	if f.ID() != "fnd-1" || f.ReleaseID() != "rel-1" || f.FaultlineID() != "fl-1" || f.CVE() != "CVE-2024-1" {
		t.Errorf("finding = %+v", f)
	}
	if f.Stage() != domain.StageIdentified {
		t.Errorf("stage = %q, want identified", f.Stage())
	}
	if _, ok := f.CurrentPosition(); ok {
		t.Error("fresh finding must have no position")
	}
	if len(f.Proposals()) != 0 || len(f.Positions()) != 0 || len(f.Components()) != 0 || f.Version() != 0 {
		t.Error("fresh finding must be empty")
	}
}

func TestNewFindingRejectsBadKey(t *testing.T) {
	cases := []struct{ id, rel, fl string }{
		{"", "rel", "fl"},
		{"id", "", "fl"},
		{"id", "rel", ""},
	}
	for _, c := range cases {
		if _, err := domain.NewFinding(domain.FindingID(c.id), c.rel, c.fl, "CVE-1"); err == nil {
			t.Errorf("NewFinding(%q,%q,%q) should fail", c.id, c.rel, c.fl)
		}
	}
}

func TestAbsorbComponent(t *testing.T) {
	f := newFinding(t)
	c := domain.MatchedComponent{PURL: "pkg:apk/openssl@3.0", Name: "openssl", Version: "3.0", Ecosystem: "Alpine"}

	added, err := f.AbsorbComponent(c)
	if err != nil || !added {
		t.Fatalf("first absorb: added=%v err=%v", added, err)
	}
	if len(f.Components()) != 1 || f.Version() != 1 {
		t.Errorf("after absorb: comps=%d version=%d", len(f.Components()), f.Version())
	}

	// Idempotent: same PURL is absorbed once.
	added, err = f.AbsorbComponent(c)
	if err != nil || added {
		t.Errorf("duplicate absorb: added=%v err=%v", added, err)
	}
	if len(f.Components()) != 1 || f.Version() != 1 {
		t.Error("duplicate absorb must not grow the finding")
	}

	// A different component is added.
	if added, _ := f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:apk/curl@8"}); !added {
		t.Error("distinct component should be added")
	}

	// Empty PURL is rejected.
	if _, err := f.AbsorbComponent(domain.MatchedComponent{Name: "x"}); err == nil {
		t.Error("empty PURL should error")
	}
}

func TestRaiseProposalFlagsForReview(t *testing.T) {
	f := newFinding(t)
	if err := f.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected)); err != nil {
		t.Fatalf("raise: %v", err)
	}
	if f.Stage() != domain.StageUnderInvestigation {
		t.Errorf("stage = %q, want under_investigation", f.Stage())
	}
	if len(f.Proposals()) != 1 || f.Version() != 1 {
		t.Errorf("proposals=%d version=%d", len(f.Proposals()), f.Version())
	}
}

func TestRaiseProposalRejections(t *testing.T) {
	f := newFinding(t)

	// Empty proposal id.
	if err := f.RaiseProposal(domain.GovernanceProposal{}); err == nil {
		t.Error("empty proposal id should error")
	}

	// A reconstituted, already-decided proposal cannot be raised.
	decided := domain.ReconstituteProposal("pd", human, domain.StanceAffected, "x", epoch, domain.StatusAccepted, human, epoch)
	if err := f.RaiseProposal(decided); !errors.Is(err, domain.ErrProposalNotOpen) {
		t.Errorf("decided raise err = %v, want ErrProposalNotOpen", err)
	}

	// Duplicate id.
	if err := f.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected)); err != nil {
		t.Fatal(err)
	}
	if err := f.RaiseProposal(proposal(t, "p1", human, domain.StanceMitigated)); !errors.Is(err, domain.ErrDuplicateProposal) {
		t.Errorf("duplicate raise err = %v, want ErrDuplicateProposal", err)
	}

	// Archived is terminal.
	if err := f.Archive(); err != nil {
		t.Fatal(err)
	}
	if err := f.RaiseProposal(proposal(t, "p2", human, domain.StanceAffected)); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("raise on archived err = %v, want ErrIllegalTransition", err)
	}
}

func TestAcceptProposalEstablishesFirstPosition(t *testing.T) {
	f := newFinding(t)
	if err := f.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected)); err != nil {
		t.Fatal(err)
	}
	pos, err := f.AcceptProposal("p1", human, epoch)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if pos.Version() != 1 || pos.Stance() != domain.StanceAffected || pos.Actor() != human {
		t.Errorf("position = %+v", pos)
	}
	if pos.Inputs().AcceptedProposalID != "p1" || pos.Inputs().FaultlineRef != "fl-1" {
		t.Errorf("inputs = %+v", pos.Inputs())
	}
	if f.Stage() != domain.StagePositionEstablished {
		t.Errorf("stage = %q, want position_established", f.Stage())
	}
	cur, ok := f.CurrentPosition()
	if !ok || cur.Version() != 1 {
		t.Errorf("current position = %+v ok=%v", cur, ok)
	}
	// The accepted proposal is retained, now decided.
	ps := f.Proposals()
	if len(ps) != 1 || ps[0].Status() != domain.StatusAccepted || ps[0].DecidedBy() != human {
		t.Errorf("proposal after accept = %+v", ps[0])
	}
}

func TestAcceptProposalRevisionKeepsStage(t *testing.T) {
	f := newFinding(t)
	_ = f.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected))
	if _, err := f.AcceptProposal("p1", human, epoch); err != nil {
		t.Fatal(err)
	}
	if err := f.MarkMonitoring(); err != nil {
		t.Fatal(err)
	}
	// A revision raised while Monitoring reopens to Under Investigation, then accept.
	_ = f.RaiseProposal(proposal(t, "p2", human, domain.StanceMitigated))
	pos, err := f.AcceptProposal("p2", human, epoch.Add(time.Hour))
	if err != nil {
		t.Fatalf("revision accept: %v", err)
	}
	if pos.Version() != 2 || pos.Stance() != domain.StanceMitigated {
		t.Errorf("revision position = %+v", pos)
	}
	if len(f.Positions()) != 2 {
		t.Errorf("positions = %d, want 2", len(f.Positions()))
	}
}

func TestAcceptProposalRejections(t *testing.T) {
	f := newFinding(t)
	_ = f.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected))

	if _, err := f.AcceptProposal("p1", domain.Actor{Kind: "bad"}, epoch); err == nil {
		t.Error("bad actor should error")
	}
	if _, err := f.AcceptProposal("p1", human, time.Time{}); err == nil {
		t.Error("zero time should error")
	}
	if _, err := f.AcceptProposal("nope", human, epoch); !errors.Is(err, domain.ErrProposalNotFound) {
		t.Errorf("unknown proposal err = %v", err)
	}
	// Accept it, then a second accept fails (already decided).
	if _, err := f.AcceptProposal("p1", human, epoch); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AcceptProposal("p1", human, epoch); !errors.Is(err, domain.ErrProposalNotOpen) {
		t.Errorf("re-accept err = %v, want ErrProposalNotOpen", err)
	}

	// Archived blocks accept.
	f2 := newFinding(t)
	_ = f2.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected))
	_ = f2.Archive()
	if _, err := f2.AcceptProposal("p1", human, epoch); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("accept on archived err = %v", err)
	}
}

func TestRejectProposal(t *testing.T) {
	f := newFinding(t)
	_ = f.RaiseProposal(proposal(t, "p1", system, domain.StanceNotAffected))

	if err := f.RejectProposal("p1", human, epoch); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if f.Stage() != domain.StageUnderInvestigation {
		t.Errorf("reject must keep investigation open, stage = %q", f.Stage())
	}
	ps := f.Proposals()
	if ps[0].Status() != domain.StatusRejected || ps[0].DecidedBy() != human {
		t.Errorf("proposal = %+v", ps[0])
	}

	// Re-reject fails; unknown fails; bad actor fails; zero time fails.
	if err := f.RejectProposal("p1", human, epoch); !errors.Is(err, domain.ErrProposalNotOpen) {
		t.Errorf("re-reject err = %v", err)
	}
	if err := f.RejectProposal("nope", human, epoch); !errors.Is(err, domain.ErrProposalNotFound) {
		t.Errorf("unknown reject err = %v", err)
	}
	if err := f.RejectProposal("p1", domain.Actor{}, epoch); err == nil {
		t.Error("bad actor reject should error")
	}
	if err := f.RejectProposal("p1", human, time.Time{}); err == nil {
		t.Error("zero-time reject should error")
	}

	// Archived blocks reject.
	f2 := newFinding(t)
	_ = f2.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected))
	_ = f2.Archive()
	if err := f2.RejectProposal("p1", human, epoch); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("reject on archived err = %v", err)
	}
}

func TestLifecycleTransitions(t *testing.T) {
	// Identified → Resolved directly is legal (D7 table).
	f := newFinding(t)
	if err := f.Resolve(); err != nil {
		t.Fatalf("identified→resolved: %v", err)
	}
	if f.Stage() != domain.StageResolved {
		t.Errorf("stage = %q", f.Stage())
	}
	// Resolved → reopen → Under Investigation.
	if err := f.Reopen(); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if f.Stage() != domain.StageUnderInvestigation {
		t.Errorf("stage = %q, want under_investigation", f.Stage())
	}

	// MarkMonitoring is illegal from Under Investigation.
	if err := f.MarkMonitoring(); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("monitoring from UI err = %v", err)
	}
	// Reopen is illegal from Under Investigation.
	if err := f.Reopen(); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("reopen from UI err = %v", err)
	}
}

func TestMarkMonitoringAndNoOps(t *testing.T) {
	f := newFinding(t)
	_ = f.RaiseProposal(proposal(t, "p1", human, domain.StanceAffected))
	_, _ = f.AcceptProposal("p1", human, epoch) // → position_established
	if err := f.MarkMonitoring(); err != nil {
		t.Fatalf("monitoring: %v", err)
	}
	if f.Stage() != domain.StageMonitoring {
		t.Errorf("stage = %q", f.Stage())
	}
	v := f.Version()
	// Re-mark Monitoring is a no-op (no version bump, no error).
	if err := f.MarkMonitoring(); err != nil {
		t.Fatalf("re-monitoring: %v", err)
	}
	if f.Version() != v {
		t.Error("no-op transition must not bump version")
	}
	// Monitoring → reopen → Under Investigation.
	if err := f.Reopen(); err != nil {
		t.Fatalf("reopen from monitoring: %v", err)
	}
}

func TestArchiveIsTerminalAndIdempotent(t *testing.T) {
	f := newFinding(t)
	if err := f.Archive(); err != nil {
		t.Fatalf("archive: %v", err)
	}
	v := f.Version()
	// Re-archive is a no-op.
	if err := f.Archive(); err != nil {
		t.Fatalf("re-archive: %v", err)
	}
	if f.Version() != v {
		t.Error("re-archive must not bump version")
	}
	// Every governed op is now illegal.
	if err := f.Resolve(); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("resolve on archived err = %v", err)
	}
	if err := f.Reopen(); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Errorf("reopen on archived err = %v", err)
	}
}

func TestReconstituteFinding(t *testing.T) {
	comps := []domain.MatchedComponent{{PURL: "pkg:apk/openssl@3"}}
	props := []domain.GovernanceProposal{proposal(t, "p1", human, domain.StanceAffected)}
	pos := domain.ReconstitutePosition(1, domain.StanceAffected, "confirmed", human,
		domain.PositionInputs{AcceptedProposalID: "p1", FaultlineRef: "fl-1"}, epoch)

	f := domain.ReconstituteFinding("fnd-9", "rel-9", "fl-1", "CVE-2024-9", comps,
		domain.StagePositionEstablished, props, []domain.Position{pos}, 7)

	if f.ID() != "fnd-9" || f.Stage() != domain.StagePositionEstablished || f.Version() != 7 {
		t.Errorf("reconstituted = %+v", f)
	}
	if cur, ok := f.CurrentPosition(); !ok || cur.Version() != 1 {
		t.Errorf("current position = %+v ok=%v", cur, ok)
	}
	// Defensive copies: mutating the returned slices must not affect the aggregate.
	f.Components()[0].PURL = "tampered"
	if f.Components()[0].PURL != "pkg:apk/openssl@3" {
		t.Error("Components() must return a defensive copy")
	}
}
