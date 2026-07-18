package domain

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

// Evaluate reports whether the proposal should be auto-accepted under this policy and,
// if so, the Actor (the policy) that owns the decision. It auto-accepts only open,
// system-raised proposals whose stance is in the policy's allow-set; everything else is
// left for a human to decide (returns false).
func (r PolicyRule) Evaluate(p GovernanceProposal) (autoAccept bool, by Actor) {
	if !p.IsOpen() || p.Proposer().Kind != ActorSystem || !r.autoAccept[p.Stance()] {
		return false, Actor{}
	}
	return true, Actor{Kind: ActorPolicy, ID: r.name}
}
