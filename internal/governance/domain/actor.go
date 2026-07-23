package domain

import "strings"

// ActorKind names who performed a governance act (raising or deciding a Proposal, or
// establishing a Position). The authority line (D11) is enforced at the app layer; the
// domain only records who acted, always (CON-0003).
type ActorKind string

const (
	// ActorHuman is an authorized human analyst — the only actor that may decide by hand.
	ActorHuman ActorKind = "human"
	// ActorAI is an AI capability — may propose only, never decide (DOM-0024).
	ActorAI ActorKind = "ai"
	// ActorPolicy is a Governance-owned auto-accept policy — the policy is the authority,
	// not the proposer (D11).
	ActorPolicy ActorKind = "policy"
	// ActorSystem is Governance's own automation (e.g. the FaultlineEnriched-driven
	// proposal, an expiry timer) — a proposer with no decision authority.
	ActorSystem ActorKind = "system"
)

// Valid reports whether k is a recognized actor kind.
func (k ActorKind) Valid() bool {
	switch k {
	case ActorHuman, ActorAI, ActorPolicy, ActorSystem:
		return true
	default:
		return false
	}
}

// Actor identifies who performed a governance act: the kind (which fixes what it is
// permitted to do) and a stable id (analyst id / capability name / policy name). The
// actor is recorded on every proposal, decision, and position for explainability
// (CON-0003).
type Actor struct {
	Kind ActorKind
	ID   string
}

// IsZero reports whether the actor is unset (no decision has been recorded yet).
func (a Actor) IsZero() bool { return a.Kind == "" && a.ID == "" }

// validActor reports an error unless the actor is well-formed.
func validActor(a Actor) error {
	if !a.Kind.Valid() {
		return errInvalidActorKind
	}
	if strings.TrimSpace(a.ID) == "" {
		return errEmptyActorID
	}
	return nil
}
