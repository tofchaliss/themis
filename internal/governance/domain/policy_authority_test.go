package domain_test

// The Δ4b immovable guardrail (D-Δ4b-6): an AI-proposed proposal can NEVER be policy-auto-accepted,
// regardless of stance or evidence. Autonomy of generation is allowed; autonomy of AUTHORITY is
// never (D3). Governance's ActorSystem gate already enforces this — this test makes it UN-ERODABLE:
// it drives every shipped auto-accept policy against an ai-proposed proposal across every stance and
// every trust class, and fails the build the moment any of them could accept. A future policy rule
// that matched on stance without the proposer check would light this up red.

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// shippedAutoAcceptPolicies is every auto-accept rule Themis ships. A new rule MUST be added here
// so the invariant covers it — that is the point: the guardrail is only as strong as the set it
// checks, so forgetting to list a rule is itself a reviewable omission.
func shippedAutoAcceptPolicies() []domain.PolicyRule {
	return []domain.PolicyRule{
		domain.AutoAcceptObservedNotAffectedPolicy(),
	}
}

func TestAIProposalNeverAutoAccepts(t *testing.T) {
	allStances := []domain.Stance{
		domain.StanceAffected, domain.StanceNotAffected, domain.StanceUnderInvestigation,
		domain.StanceMitigated, domain.StanceAcceptedRisk, domain.StanceDeferred,
	}
	allTrust := []value.TrustClass{value.TrustObserved, value.TrustAsserted, value.TrustInferred, ""}
	aiProposer := domain.Actor{Kind: domain.ActorAI, ID: "consistency-analyst"}

	for _, policy := range shippedAutoAcceptPolicies() {
		for _, stance := range allStances {
			for _, trust := range allTrust {
				p, err := domain.NewGovernanceProposal("p-1", aiProposer, stance, "autonomous advisory",
					time.Unix(1_700_000_000, 0), trust)
				if err != nil {
					t.Fatalf("build proposal: %v", err)
				}
				if accept, by := policy.Evaluate(p); accept {
					t.Fatalf("AUTHORITY BREACH: policy %q auto-accepted an AI proposal "+
						"(stance=%s trust=%q, decided_by=%+v). Autonomy of authority is forbidden (D3/D-Δ4b-6).",
						policy.Name(), stance, trust, by)
				}
			}
		}
	}
}

// The companion: the SAME shipped policy DOES accept the equivalent system-raised proposal (where a
// rule allows it), so the test above is proving the ai-exclusion — not merely that the policy never
// accepts anything.
func TestSystemProposalStillAutoAcceptsUnderItsRule(t *testing.T) {
	sysProposer := domain.Actor{Kind: domain.ActorSystem, ID: "vex-overlay"}
	p, err := domain.NewGovernanceProposal("p-2", sysProposer, domain.StanceNotAffected,
		"withdrawn upstream", time.Unix(1_700_000_000, 0), value.TrustObserved)
	if err != nil {
		t.Fatal(err)
	}
	if accept, _ := domain.AutoAcceptObservedNotAffectedPolicy().Evaluate(p); !accept {
		t.Fatal("the shipped rule must accept a system-raised not_affected on Observed evidence — " +
			"otherwise the ai-exclusion test above proves nothing")
	}
}
