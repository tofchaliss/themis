package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

func proposalWithTrust(t *testing.T, proposer domain.Actor, c value.TrustClass) domain.GovernanceProposal {
	t.Helper()
	p, err := domain.NewGovernanceProposal("p1", proposer, domain.StanceNotAffected, "why", time.Unix(1, 0).UTC(), c)
	if err != nil {
		t.Fatalf("build proposal: %v", err)
	}
	return p
}

func TestConstitutionallyAutoAcceptable(t *testing.T) {
	system := domain.Actor{Kind: domain.ActorSystem, ID: "rule"}
	for _, tc := range []struct {
		name  string
		class value.TrustClass
		want  bool
	}{
		{"observed evidence is eligible", value.TrustObserved, true},
		{"asserted evidence is eligible — policy decides", value.TrustAsserted, true},
		{"inferred evidence is barred", value.TrustInferred, false},
		{"unset evidence fails closed", value.TrustClass(""), false},
		{"malformed evidence fails closed", value.TrustClass("garbage"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.ConstitutionallyAutoAcceptable(proposalWithTrust(t, system, tc.class)); got != tc.want {
				t.Fatalf("ConstitutionallyAutoAcceptable(%q) = %v, want %v", tc.class, got, tc.want)
			}
		})
	}
}

// The laundering case the whole trust model exists to close (T1/T3). The proposer is
// ActorSystem — Governance's own deterministic automation — so every producer-based check
// says "eligible". But its evidence included an AI-derived fact, so the conclusion is
// Inferred and it is barred. Producer-based classification cannot see this: it asks who
// spoke last, and a deterministic rule spoke last.
func TestConstitutionallyAutoAcceptable_DeterministicProposerCannotLaunderInferredEvidence(t *testing.T) {
	system := domain.Actor{Kind: domain.ActorSystem, ID: "version-range"}
	p := proposalWithTrust(t, system, value.TrustInferred)

	if p.Proposer().Kind != domain.ActorSystem {
		t.Fatalf("precondition: proposer should be the system, got %q", p.Proposer().Kind)
	}
	if domain.ConstitutionallyAutoAcceptable(p) {
		t.Fatal("a system-raised proposal resting on Inferred evidence must still be barred — " +
			"determinism launders nothing")
	}
}

// The bar is an invariant, not a setting: no policy configuration can make Inferred
// evidence auto-acceptable, because the constitutional stage runs before policy is
// consulted at all. Even a policy that allows the exact stance cannot reach it.
func TestInferredIsBarredRegardlessOfPolicyConfiguration(t *testing.T) {
	system := domain.Actor{Kind: domain.ActorSystem, ID: "rule"}
	p := proposalWithTrust(t, system, value.TrustInferred)

	for _, rule := range []domain.PolicyRule{
		domain.NewPolicyRule("permissive", domain.StanceNotAffected),
		domain.NewPolicyRule("very-permissive",
			domain.StanceNotAffected, domain.StanceAffected, domain.StanceMitigated, domain.StanceAcceptedRisk),
	} {
		// The policy itself would accept it — which is precisely why the constitutional
		// stage must be evaluated first and cannot be configured.
		if ok, _ := rule.Evaluate(p); !ok {
			t.Fatalf("precondition: policy %q should match this stance", rule.Name())
		}
		if domain.ConstitutionallyAutoAcceptable(p) {
			t.Fatalf("policy %q must not be able to enable Inferred auto-acceptance", rule.Name())
		}
	}
}

// T1 removes the producer as a TRUST-bearing category, not as an AUTHORITY one. Dropping
// the system-proposer check would newly let policy auto-accept a human's proposal, which
// DOM-0024 does not permit. Decisions and evidence are different axes (T12).
func TestPolicyStillGatesOnAuthorityNotTrust(t *testing.T) {
	rule := domain.NewPolicyRule("auto-na", domain.StanceNotAffected)
	human := domain.Actor{Kind: domain.ActorHuman, ID: "analyst-1"}
	ai := domain.Actor{Kind: domain.ActorAI, ID: "recommend_position@v1"}

	// Both carry perfectly good Observed evidence, so the constitutional stage passes...
	for _, proposer := range []domain.Actor{human, ai} {
		p := proposalWithTrust(t, proposer, value.TrustObserved)
		if !domain.ConstitutionallyAutoAcceptable(p) {
			t.Fatalf("precondition: Observed evidence should clear the constitutional stage for %q", proposer.Kind)
		}
		// ...and policy still refuses, because neither has authority to be auto-decided.
		if ok, _ := rule.Evaluate(p); ok {
			t.Errorf("policy must not auto-accept a %q proposal", proposer.Kind)
		}
	}
}

// The shipped policy (EDR-GOVERNANCE-01 D15) auto-accepts exactly one shape. The case that
// carries the decision is the THIRD one: an Asserted vendor not_affected passes the
// constitutional bar (T4 bars only Inferred) and is still refused, because the rule's own
// evidence floor is Observed. That floor is what keeps "vendor VEX is gathered, not obeyed"
// (EDR-VEX-01) true in code rather than only in prose.
func TestAutoAcceptObservedNotAffectedPolicy(t *testing.T) {
	system := domain.Actor{Kind: domain.ActorSystem, ID: "version-range"}
	human := domain.Actor{Kind: domain.ActorHuman, ID: "analyst"}
	ai := domain.Actor{Kind: domain.ActorAI, ID: "recommend_position@v1"}
	rule := domain.AutoAcceptObservedNotAffectedPolicy()

	for _, tc := range []struct {
		name    string
		by      domain.Actor
		stance  domain.Stance
		trust   value.TrustClass
		want    bool
		because string
	}{
		{"the shipped case: provable suppression", system, domain.StanceNotAffected, value.TrustObserved, true,
			"re-derivable arithmetic over public ranges — nobody has to be believed"},
		{"vendor VEX is gathered, not obeyed", system, domain.StanceNotAffected, value.TrustAsserted, false,
			"passes T4, refused by the rule's Observed floor — a vendor's word waits for a human"},
		{"AI never reaches policy", system, domain.StanceNotAffected, value.TrustInferred, false,
			"barred constitutionally before policy, and by the floor as well"},
		{"no automatic affected", system, domain.StanceAffected, value.TrustObserved, false,
			"an automatic affected would be a decision nobody made about work someone must do"},
		{"a human's proposal is never auto-accepted", human, domain.StanceNotAffected, value.TrustObserved, false,
			"the authority axis (D11) is separate from the evidence axis"},
		{"an AI's proposal is never auto-accepted", ai, domain.StanceNotAffected, value.TrustObserved, false,
			"same authority axis, regardless of how good its evidence is"},
		{"unstated evidence fails closed", system, domain.StanceNotAffected, value.TrustClass(""), false,
			"an unset class folds to Inferred, so it clears no floor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := domain.NewGovernanceProposal("p1", tc.by, tc.stance, "r", time.Now(), tc.trust)
			if err != nil {
				t.Fatalf("NewGovernanceProposal: %v", err)
			}
			got, by := rule.Evaluate(p)
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v — %s", got, tc.want, tc.because)
			}
			if got && (by.Kind != domain.ActorPolicy || by.ID != "auto-not-affected-observed") {
				t.Fatalf("deciding actor = %+v, want the POLICY as authority, not the proposer", by)
			}
		})
	}
}

// A rule with no declared floor keeps its pre-D15 behaviour (the constitutional bar alone), so
// the floor is opt-in and a rule that forgets one is permissive rather than silently strict —
// the failure mode that is loud in review instead of invisible at runtime.
func TestPolicyRule_NoFloorFallsBackToTheConstitutionalBarAlone(t *testing.T) {
	rule := domain.NewPolicyRule("legacy", domain.StanceNotAffected)
	system := domain.Actor{Kind: domain.ActorSystem, ID: "vex-applicability"}
	p, _ := domain.NewGovernanceProposal("p1", system, domain.StanceNotAffected, "r", time.Now(), value.TrustAsserted)
	if ok, _ := rule.Evaluate(p); !ok {
		t.Fatal("a floor-less rule must still accept Asserted — the floor is the rule's choice, not the engine's")
	}
}

// A stronger-than-required class satisfies the floor: the comparison is "at least as strong as",
// not equality.
func TestPolicyRule_StrongerEvidenceThanRequiredStillPasses(t *testing.T) {
	rule := domain.NewPolicyRule("lenient", domain.StanceNotAffected).RequiringEvidence(value.TrustAsserted)
	system := domain.Actor{Kind: domain.ActorSystem, ID: "version-range"}
	p, _ := domain.NewGovernanceProposal("p1", system, domain.StanceNotAffected, "r", time.Now(), value.TrustObserved)
	if ok, _ := rule.Evaluate(p); !ok {
		t.Fatal("Observed must satisfy an Asserted floor — the floor is a minimum, not a match")
	}
}

// An invalid class must not read as "no floor" and quietly widen the rule.
func TestPolicyRule_InvalidFloorIsIgnoredNotTreatedAsNoFloor(t *testing.T) {
	rule := domain.NewPolicyRule("typo", domain.StanceNotAffected).
		RequiringEvidence(value.TrustObserved).
		RequiringEvidence(value.TrustClass("observd"))
	system := domain.Actor{Kind: domain.ActorSystem, ID: "vex-applicability"}
	p, _ := domain.NewGovernanceProposal("p1", system, domain.StanceNotAffected, "r", time.Now(), value.TrustAsserted)
	if ok, _ := rule.Evaluate(p); ok {
		t.Fatal("a typo'd class must leave the existing floor intact, never widen the policy")
	}
}
