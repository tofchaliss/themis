package domain

import "github.com/themis-project/themis/internal/kernel/value"

// PolicyRule is a Governance-owned auto-accept rule (D11): a pure, deterministic policy
// that may accept certain system-raised proposals without a human — e.g. "CVE withdrawn
// upstream → auto-accept Not-Affected" (D6). The **policy** is the authority, not the
// proposer (DOM-0024 / CON-0009): only proposals raised by Governance's own automation
// (ActorSystem) are eligible; a human's or an AI's proposal is never auto-accepted. The
// evaluation is pure so it is fully explainable and replayable.
type PolicyRule struct {
	name       string
	autoAccept map[Stance]bool
}

// NewPolicyRule builds a named auto-accept policy for the given stances. A nil/empty
// stance set yields a policy that never auto-accepts (a valid, inert rule).
func NewPolicyRule(name string, stances ...Stance) PolicyRule {
	set := make(map[Stance]bool, len(stances))
	for _, s := range stances {
		if s.Valid() {
			set[s] = true
		}
	}
	return PolicyRule{name: name, autoAccept: set}
}

// Name returns the policy's stable name (recorded as the deciding Actor's id).
func (r PolicyRule) Name() string { return r.name }

// ConstitutionallyAutoAcceptable reports whether a proposal is even ELIGIBLE for automatic
// acceptance, before any configurable policy is consulted (EDR-TRUST-01 T4/T6).
//
// It is a fixed rule with no configuration surface: a proposal resting on **Inferred**
// evidence may never be auto-accepted, under any policy. That is the constitutional
// expression of "autonomy of generation, yes; autonomy of authority, never"
// (DOM-0024 / CON-0015 / INT-0056).
//
// It reads the proposal's **evidence**, not its proposer (T1) — so a deterministic rule
// that consumed an AI-derived fact is barred exactly like the AI would have been. Producer-
// based classification cannot see that case, because it asks who spoke last.
//
// An unset class is treated as Inferred by value.MaxTrust, so a proposal raised without
// stating its evidence fails closed rather than slipping through as trusted.
func ConstitutionallyAutoAcceptable(p GovernanceProposal) bool {
	return value.MaxTrust(p.EvidenceTrust()) != value.TrustInferred
}

// Evaluate reports whether the proposal should be auto-accepted under this policy and,
// if so, the Actor (the policy) that owns the decision. It auto-accepts only open,
// system-raised proposals whose stance is in the policy's allow-set; everything else is
// left for a human to decide (returns false).
//
// The system-raised check is an **authority** rule, not a trust rule, and survives
// EDR-TRUST-01 T1 intact: T1 removes the producer as a *trust-bearing* category, and trust
// now lives in the constitutional stage above. Who may auto-decide is a separate axis —
// dropping this check would newly let policy auto-accept a **human's** proposal, which
// nothing intends and DOM-0024 does not permit. Decisions and evidence are different
// concepts (T12), and this is the decision axis.
func (r PolicyRule) Evaluate(p GovernanceProposal) (autoAccept bool, by Actor) {
	if !p.IsOpen() || p.Proposer().Kind != ActorSystem || !r.autoAccept[p.Stance()] {
		return false, Actor{}
	}
	return true, Actor{Kind: ActorPolicy, ID: r.name}
}
