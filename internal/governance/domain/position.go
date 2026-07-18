package domain

import "time"

// PositionInputs records the evidence a Position version rested on, so any past decision
// is fully reconstructable (CON-0003 / D3): the accepted Governance Proposal and a
// reference to the Faultline knowledge state at the time it was established. The
// Faultline is referenced by immutable id (a string), never copied (D1).
type PositionInputs struct {
	AcceptedProposalID ProposalID
	FaultlineRef       string
}

// Position is one immutable version of an Enterprise Position — the authoritative,
// committed enterprise decision about a Finding at a point in time (D3). Each accepted
// proposal establishes a new version (v1, v2, …); prior versions are retained forever,
// never edited. A Position records its stance, rationale, the actor that established it,
// the inputs it rested on, and the timestamp. It has no exported fields — construction
// goes through the Finding aggregate, and it is read-only thereafter.
type Position struct {
	version       int
	stance        Stance
	rationale     string
	actor         Actor
	inputs        PositionInputs
	establishedAt time.Time
}

// ReconstitutePosition rebuilds a Position version from persisted state (store adapter).
// Persistence is trusted; no re-validation is performed.
func ReconstitutePosition(version int, stance Stance, rationale string, actor Actor, inputs PositionInputs, establishedAt time.Time) Position {
	return Position{
		version:       version,
		stance:        stance,
		rationale:     rationale,
		actor:         actor,
		inputs:        inputs,
		establishedAt: establishedAt.UTC(),
	}
}

// Version returns the 1-based Position version number (v1 is the first).
func (p Position) Version() int { return p.version }

// Stance returns the official enterprise decision value.
func (p Position) Stance() Stance { return p.stance }

// Rationale returns the recorded justification for the decision.
func (p Position) Rationale() string { return p.rationale }

// Actor returns who established this version (human, policy, or AI via governance).
func (p Position) Actor() Actor { return p.actor }

// Inputs returns the references this version rested on (accepted proposal + Faultline ref).
func (p Position) Inputs() PositionInputs { return p.inputs }

// EstablishedAt returns when this version was committed.
func (p Position) EstablishedAt() time.Time { return p.establishedAt }

// IsZero reports whether the Position is unset (a Finding with no decision yet).
func (p Position) IsZero() bool { return p.version == 0 }
