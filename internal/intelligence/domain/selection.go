package domain

import "strings"

// SelectionType is a **user-addressable entry point** into an AI capability (EDR-TRUST-01
// T9) — the kind of thing a person can point at in an interface.
//
// Selection Types are deliberately NOT domain entities. A type qualifies only when both
// hold: it is addressable today (a stable id that could appear in a URL), and a named use
// case treats it as the thing the user *picks* rather than background context the system
// gathers. Everything else — Enterprise Positions, Faultlines, vendor VEX, policies,
// historical decisions, estate and blast-radius — is Decision Context: assembled on the
// user's behalf, never selected.
//
// Enterprise Positions are the instructive rejection: a Position has no independent
// identity (it is addressed only as a version of a Finding) and no use case asks a user to
// pick one, so admitting it would have exposed an internal versioning construct as a
// first-class API concept before it was part of anyone's experience.
type SelectionType string

const (
	// SelectionFinding is a Governance Finding — Book IV UC-003/004/005 select one.
	SelectionFinding SelectionType = "finding"
	// SelectionRelease is a Registry Release — Book IV UC-001/002/006 select one, and the
	// actor-view diagram makes it the primary entry point ("Select Release → View Findings").
	SelectionRelease SelectionType = "release"
)

// Valid reports whether t is an admitted Selection Type.
func (t SelectionType) Valid() bool {
	switch t {
	case SelectionFinding, SelectionRelease:
		return true
	default:
		return false
	}
}

// String returns the type label.
func (t SelectionType) String() string { return string(t) }

// Selection is what a capability is invoked against: a type plus a **set** of identifiers
// of that type (EDR-TRUST-01 T9).
//
// It is a set rather than a single id because Book IV UC-004 has the user tick several
// Findings before asking for a VEX draft. Modelling that as "several of kind finding" needs
// no new type; modelling it with a single id would have required a category meaning
// "several of the first category", which is a smell.
type Selection struct {
	Type SelectionType
	IDs  []string
}

// NewSelection builds a Selection, trimming blank ids. It performs no cardinality check —
// how many a capability accepts is the capability's declaration, checked by Accepts.
func NewSelection(t SelectionType, ids ...string) Selection {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if s := strings.TrimSpace(id); s != "" {
			out = append(out, s)
		}
	}
	return Selection{Type: t, IDs: out}
}

// First returns the first identifier, or "" when the Selection is empty. Convenient for the
// single-subject capabilities that are the only kind today.
func (s Selection) First() string {
	if len(s.IDs) == 0 {
		return ""
	}
	return s.IDs[0]
}

// Accepts reports whether this capability may be invoked against the given Selection: the
// type must match what it declared, and the count must fall inside its declared bounds.
//
// Cardinality is a **capability declaration, not a global setting** — which is what lets it
// double as the fan-out guard (T9). A capability that handles one Finding declares a maximum
// of one, and the boundary is enforced at the door, before any projection is built or any
// provider is called. A global "never look up more than N things" knob would be the kind of
// setting nobody tunes correctly.
func (c Capability) Accepts(sel Selection) bool {
	if sel.Type != c.SelectionType || !sel.Type.Valid() {
		return false
	}
	n := len(sel.IDs)
	return n >= c.MinSelection && n <= c.MaxSelection
}
