package domain

// Stage is the Faultline's lifecycle stage — Book II §6.6's five names realized as a
// governed, forward-only maturity ladder (D7): Created → Enriched → Correlated →
// Mature → Superseded. It is monotonic ("highest milestone reached"); reaching a later
// milestone implies the earlier ones. Superseded is terminal and reachable from any
// stage (a merged/replaced card or a withdrawn/rejected CVE).
type Stage string

const (
	StageCreated    Stage = "created"
	StageEnriched   Stage = "enriched"
	StageCorrelated Stage = "correlated"
	StageMature     Stage = "mature"
	StageSuperseded Stage = "superseded"
)

// rank orders the ladder; -1 marks an unrecognized stage.
func (s Stage) rank() int {
	switch s {
	case StageCreated:
		return 0
	case StageEnriched:
		return 1
	case StageCorrelated:
		return 2
	case StageMature:
		return 3
	case StageSuperseded:
		return 4
	default:
		return -1
	}
}

// Valid reports whether s is a recognized lifecycle stage.
func (s Stage) Valid() bool { return s.rank() >= 0 }

// advanceTo returns the later of the current stage and target on the forward-only
// ladder: an earlier target never regresses the stage, and once Superseded (terminal)
// the stage never changes. Superseded is reachable from any non-terminal stage.
func (s Stage) advanceTo(target Stage) Stage {
	switch {
	case s == StageSuperseded:
		return s // terminal
	case target == StageSuperseded:
		return StageSuperseded // reachable from anywhere
	case target.rank() > s.rank():
		return target
	default:
		return s
	}
}
