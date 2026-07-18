package domain

// Stance is an Enterprise Position's decision value, as Communication receives it from
// Governance (over the Position event + read API). Communication re-declares the vocabulary
// rather than importing Governance (no cross-context imports); it never invents or reinterprets
// a stance — it carries the Position's stance verbatim into every artifact (the D3
// stance-equality invariant).
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

// Phrase returns a deterministic human-readable rendering of the stance for advisory /
// notification presentation. Presentation may vary; the stance value itself never does.
func (s Stance) Phrase() string {
	switch s {
	case StanceAffected:
		return "affected"
	case StanceNotAffected:
		return "not affected"
	case StanceUnderInvestigation:
		return "under investigation"
	case StanceMitigated:
		return "mitigated"
	case StanceAcceptedRisk:
		return "affected — risk accepted"
	case StanceDeferred:
		return "deferred"
	default:
		return string(s)
	}
}

// VEXStatus maps the stance to its VEX analysis status (CycloneDX / OpenVEX vocabulary).
// This is a presentation mapping of the *same* conclusion, never a reinterpretation (D3).
func (s Stance) VEXStatus() string {
	switch s {
	case StanceNotAffected:
		return "not_affected"
	case StanceMitigated:
		return "fixed"
	case StanceUnderInvestigation, StanceDeferred:
		return "under_investigation"
	default: // affected, accepted_risk
		return "affected"
	}
}
