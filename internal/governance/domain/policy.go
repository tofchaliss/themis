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
	// requiredTrust is the rule's own evidence floor (D15). Empty ⇒ no floor beyond the
	// constitutional bar, which admits Asserted — so a shipped rule states its floor
	// explicitly and a rule that forgets one is permissive, never silently strict.
	requiredTrust value.TrustClass
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

// RequiringEvidence sets the rule's evidence floor and returns it for chaining (D15): the
// proposal's evidence class must be at least as strong as `required`.
//
// This is deliberately **stricter than the constitution**. T4 bars only Inferred, which leaves
// **Asserted** — a vendor's word — auto-acceptable. Auto-accepting on a vendor statement alone
// would contradict EDR-VEX-01's "Gathering Is Not Knowing", where vendor VEX is gathered, not
// obeyed. The shipped rule therefore demands **Observed**: evidence anyone can re-derive.
//
// An invalid class is ignored rather than treated as "no floor", so a typo cannot quietly widen
// a policy.
func (r PolicyRule) RequiringEvidence(required value.TrustClass) PolicyRule {
	if required.Valid() {
		r.requiredTrust = required
	}
	return r
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
	if !r.evidenceMeetsFloor(p.EvidenceTrust()) {
		return false, Actor{}
	}
	return true, Actor{Kind: ActorPolicy, ID: r.name}
}

// evidenceMeetsFloor reports whether the proposal's evidence is at least as strong as the
// rule's floor (D15). No floor ⇒ the constitutional bar alone governs.
//
// The comparison reuses value.MaxTrust rather than exporting a rank: MaxTrust returns the
// HIGHEST-RISK of the two classes, so it equals `required` exactly when the actual class is
// `required` or better. An unset actual class folds to Inferred inside MaxTrust, so a proposal
// that never stated its evidence fails every floor — the same fail-closed behaviour the
// constitutional stage relies on.
func (r PolicyRule) evidenceMeetsFloor(actual value.TrustClass) bool {
	if r.requiredTrust == "" {
		return true
	}
	return value.MaxTrust(actual, r.requiredTrust) == r.requiredTrust
}

// AutoAcceptObservedNotAffectedPolicy is THE auto-accept rule Themis ships (EDR-GOVERNANCE-01
// D15). It auto-accepts a proposal only when every one of these holds:
//
//   - it is **open** — nothing already decided is re-decided;
//   - it was raised by **ActorSystem** — the authority axis of D11: a human's or an AI's
//     proposal is never auto-accepted, whatever its evidence;
//   - its stance is **not_affected** — only a suppressing stance is eligible. An automatic
//     `affected` would be a decision nobody made about work someone must now do, and leaving it
//     open costs nothing since an undecided Finding already sits at full residual_priority (D14);
//   - its evidence is **Observed** — re-derivable by anyone. In practice that is the
//     version-range verdict (arithmetic over public ranges, T5) and an upstream CVE withdrawal.
//
// The Observed floor, not the constitutional bar, is what keeps vendor VEX out: T4 bars only
// Inferred, so Asserted — a vendor's word about their own build — would otherwise auto-suppress
// a Finding. EDR-VEX-01 is explicit that vendor VEX is gathered, not obeyed, so it raises a
// proposal and waits for a human. This rule is the deterministic half of that promise.
func AutoAcceptObservedNotAffectedPolicy() PolicyRule {
	return NewPolicyRule("auto-not-affected-observed", StanceNotAffected).
		RequiringEvidence(value.TrustObserved)
}
