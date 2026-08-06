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
