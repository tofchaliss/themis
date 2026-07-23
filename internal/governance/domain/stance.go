package domain

// Stance is an Enterprise Position's value — the official enterprise decision about a
// Finding. Book II §8.2 calls these "examples rather than fixed vocabulary", so the set
// is controlled but extensible (D3): adding a value later is a localized change here.
type Stance string

const (
	StanceAffected           Stance = "affected"
	StanceNotAffected        Stance = "not_affected"
	StanceUnderInvestigation Stance = "under_investigation"
	StanceMitigated          Stance = "mitigated"
	StanceAcceptedRisk       Stance = "accepted_risk"
	StanceDeferred           Stance = "deferred"
)

// Valid reports whether s is a recognized stance.
func (s Stance) Valid() bool {
	switch s {
	case StanceAffected, StanceNotAffected, StanceUnderInvestigation,
		StanceMitigated, StanceAcceptedRisk, StanceDeferred:
		return true
	default:
		return false
	}
}
