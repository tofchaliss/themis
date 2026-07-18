package domain

// Stage is the Finding's investigation lifecycle stage — Book II §7.5's six names (D7):
// Identified → Under Investigation → Position Established → Monitoring → Resolved →
// Archived. Unlike the Faultline's forward-only ladder (EDR-KNOWLEDGE-01 D7), this
// lifecycle has a governed reopen path (Monitoring/Resolved → Under Investigation) taken
// when new knowledge raises a proposal. Archived is terminal (the release is retired).
// The Finding lifecycle tracks the *investigation*; the Position versions track the
// *decision* — the two are loosely coupled (a Position revision never resets the stage).
type Stage string

const (
	// StageIdentified — created from a component match (D5); no Position yet.
	StageIdentified Stage = "identified"
	// StageUnderInvestigation — proposals in flight / flagged for review (D6).
	StageUnderInvestigation Stage = "under_investigation"
	// StagePositionEstablished — a first Enterprise Position has been accepted (D3/D4).
	StagePositionEstablished Stage = "position_established"
	// StageMonitoring — position set, watching for change.
	StageMonitoring Stage = "monitoring"
	// StageResolved — concern closed (fixed / mitigated / not-affected); reopenable.
	StageResolved Stage = "resolved"
	// StageArchived — terminal (release retired).
	StageArchived Stage = "archived"
)

// Valid reports whether s is a recognized lifecycle stage.
func (s Stage) Valid() bool {
	switch s {
	case StageIdentified, StageUnderInvestigation, StagePositionEstablished,
		StageMonitoring, StageResolved, StageArchived:
		return true
	default:
		return false
	}
}

// stageTransitions is the governed transition table (D7). A transition to the current
// stage is always a no-op (handled by the caller) and not listed here. Archived is
// terminal — no outgoing transitions.
var stageTransitions = map[Stage][]Stage{
	StageIdentified:          {StageUnderInvestigation, StagePositionEstablished, StageResolved, StageArchived},
	StageUnderInvestigation:  {StagePositionEstablished, StageResolved, StageArchived},
	StagePositionEstablished: {StageMonitoring, StageUnderInvestigation, StageResolved, StageArchived},
	StageMonitoring:          {StageUnderInvestigation, StageResolved, StageArchived},
	StageResolved:            {StageUnderInvestigation, StageArchived},
	StageArchived:            {},
}

// canTransitionTo reports whether moving from s to target is a legal governed transition
// (D7). Staying put (target == s) is legal and handled as a no-op by callers.
func (s Stage) canTransitionTo(target Stage) bool {
	if target == s {
		return true
	}
	for _, allowed := range stageTransitions[s] {
		if allowed == target {
			return true
		}
	}
	return false
}
