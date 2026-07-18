package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

var epoch = time.Unix(1_700_000_000, 0).UTC()

func TestActorKindValid(t *testing.T) {
	for _, k := range []domain.ActorKind{domain.ActorHuman, domain.ActorAI, domain.ActorPolicy, domain.ActorSystem} {
		if !k.Valid() {
			t.Errorf("%q should be valid", k)
		}
	}
	if domain.ActorKind("wizard").Valid() {
		t.Error("unknown actor kind should be invalid")
	}
}

func TestActorIsZero(t *testing.T) {
	if !(domain.Actor{}).IsZero() {
		t.Error("empty actor should be zero")
	}
	if (domain.Actor{Kind: domain.ActorHuman, ID: "alice"}).IsZero() {
		t.Error("populated actor should not be zero")
	}
}

func TestStanceValid(t *testing.T) {
	for _, s := range []domain.Stance{
		domain.StanceAffected, domain.StanceNotAffected, domain.StanceUnderInvestigation,
		domain.StanceMitigated, domain.StanceAcceptedRisk, domain.StanceDeferred,
	} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	if domain.Stance("teapot").Valid() {
		t.Error("unknown stance should be invalid")
	}
}

func TestStageValid(t *testing.T) {
	for _, s := range []domain.Stage{
		domain.StageIdentified, domain.StageUnderInvestigation, domain.StagePositionEstablished,
		domain.StageMonitoring, domain.StageResolved, domain.StageArchived,
	} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	if domain.Stage("limbo").Valid() {
		t.Error("unknown stage should be invalid")
	}
}

func TestReconstitutePosition(t *testing.T) {
	in := domain.PositionInputs{AcceptedProposalID: "p1", FaultlineRef: "fl-1"}
	actor := domain.Actor{Kind: domain.ActorHuman, ID: "alice"}
	pos := domain.ReconstitutePosition(2, domain.StanceMitigated, "fixed upstream", actor, in, epoch)

	if pos.Version() != 2 || pos.Stance() != domain.StanceMitigated || pos.Rationale() != "fixed upstream" {
		t.Errorf("position = %+v", pos)
	}
	if pos.Actor() != actor || pos.Inputs() != in || !pos.EstablishedAt().Equal(epoch) {
		t.Errorf("position provenance = %+v / %+v / %v", pos.Actor(), pos.Inputs(), pos.EstablishedAt())
	}
	if pos.IsZero() {
		t.Error("reconstituted position should not be zero")
	}
	if !(domain.Position{}).IsZero() {
		t.Error("empty position should be zero")
	}
}

func TestNewGovernanceProposal(t *testing.T) {
	proposer := domain.Actor{Kind: domain.ActorAI, ID: "triage-analyst"}
	p, err := domain.NewGovernanceProposal("p1", proposer, domain.StanceNotAffected, "vendor VEX", epoch)
	if err != nil {
		t.Fatalf("valid proposal: %v", err)
	}
	if p.ID() != "p1" || p.Proposer() != proposer || p.Stance() != domain.StanceNotAffected {
		t.Errorf("proposal = %+v", p)
	}
	if p.Rationale() != "vendor VEX" || !p.RaisedAt().Equal(epoch) || p.Status() != domain.StatusProposed {
		t.Errorf("proposal fields = %+v", p)
	}
	if !p.IsOpen() {
		t.Error("fresh proposal should be open")
	}
	if !p.DecidedBy().IsZero() || !p.DecidedAt().IsZero() {
		t.Error("fresh proposal should carry no decision")
	}
}

func TestNewGovernanceProposalRejectsBadInput(t *testing.T) {
	good := domain.Actor{Kind: domain.ActorHuman, ID: "alice"}
	cases := []struct {
		name     string
		id       domain.ProposalID
		proposer domain.Actor
		stance   domain.Stance
		at       time.Time
	}{
		{"empty id", "", good, domain.StanceAffected, epoch},
		{"bad actor kind", "p1", domain.Actor{Kind: "wizard", ID: "x"}, domain.StanceAffected, epoch},
		{"empty actor id", "p1", domain.Actor{Kind: domain.ActorHuman}, domain.StanceAffected, epoch},
		{"invalid stance", "p1", good, domain.Stance("nope"), epoch},
		{"zero time", "p1", good, domain.StanceAffected, time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := domain.NewGovernanceProposal(c.id, c.proposer, c.stance, "", c.at); err == nil {
				t.Fatalf("%s: expected error", c.name)
			}
		})
	}
}

func TestReconstituteProposal(t *testing.T) {
	proposer := domain.Actor{Kind: domain.ActorSystem, ID: "faultline-enriched"}
	decider := domain.Actor{Kind: domain.ActorPolicy, ID: "auto-not-affected"}
	p := domain.ReconstituteProposal("p9", proposer, domain.StanceNotAffected, "withdrawn", epoch,
		domain.StatusAccepted, decider, epoch.Add(time.Hour))

	if p.Status() != domain.StatusAccepted || p.IsOpen() {
		t.Error("reconstituted accepted proposal should not be open")
	}
	if p.DecidedBy() != decider || !p.DecidedAt().Equal(epoch.Add(time.Hour)) {
		t.Errorf("decision = %+v / %v", p.DecidedBy(), p.DecidedAt())
	}
}

func TestPolicyRuleEvaluate(t *testing.T) {
	rule := domain.NewPolicyRule("auto-not-affected", domain.StanceNotAffected, domain.Stance("bogus"))
	if rule.Name() != "auto-not-affected" {
		t.Errorf("name = %q", rule.Name())
	}

	system := domain.Actor{Kind: domain.ActorSystem, ID: "faultline-enriched"}
	human := domain.Actor{Kind: domain.ActorHuman, ID: "alice"}

	// Auto-accepts an open, system-raised proposal whose stance is in the allow-set.
	sysNotAffected, _ := domain.NewGovernanceProposal("p1", system, domain.StanceNotAffected, "withdrawn", epoch)
	if ok, by := rule.Evaluate(sysNotAffected); !ok || by.Kind != domain.ActorPolicy || by.ID != "auto-not-affected" {
		t.Errorf("system not-affected should auto-accept via policy: ok=%v by=%+v", ok, by)
	}

	// Not a system proposer → never auto-accept (human keeps authority).
	humanNotAffected, _ := domain.NewGovernanceProposal("p2", human, domain.StanceNotAffected, "manual", epoch)
	if ok, _ := rule.Evaluate(humanNotAffected); ok {
		t.Error("human proposal must not be auto-accepted")
	}

	// Stance not in the allow-set → not auto-accepted.
	sysAffected, _ := domain.NewGovernanceProposal("p3", system, domain.StanceAffected, "confirmed", epoch)
	if ok, _ := rule.Evaluate(sysAffected); ok {
		t.Error("stance outside allow-set must not be auto-accepted")
	}

	// Already-decided proposal → not open → not auto-accepted.
	decided := domain.ReconstituteProposal("p4", system, domain.StanceNotAffected, "x", epoch,
		domain.StatusRejected, human, epoch)
	if ok, _ := rule.Evaluate(decided); ok {
		t.Error("decided proposal must not be auto-accepted")
	}

	// An empty policy never auto-accepts.
	if ok, _ := domain.NewPolicyRule("inert").Evaluate(sysNotAffected); ok {
		t.Error("empty policy must not auto-accept")
	}
}
