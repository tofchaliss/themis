package domain

// Stance is Intelligence's view of an Enterprise-Position disposition — the wire
// vocabulary shared with Governance. Intelligence owns no truth (D1), so this is a
// value mirror of Governance's stance, never Governance's type (no cross-context
// import). Δ1's recommend_position may propose only the disposition subset below;
// the human/process stances (under_investigation / accepted_risk / deferred) are
// decisions Intelligence must never make (Revision 2 Δ1 cut).
type Stance string

const (
	StanceAffected    Stance = "affected"
	StanceNotAffected Stance = "not_affected"
	StanceMitigated   Stance = "mitigated"
)

// Recommendable reports whether s is a disposition an AI capability may propose.
// Only affected / not_affected / mitigated qualify; every other value (including
// the human/process stances) is rejected by stage-2 business validation (D7).
func (s Stance) Recommendable() bool {
	switch s {
	case StanceAffected, StanceNotAffected, StanceMitigated:
		return true
	default:
		return false
	}
}
