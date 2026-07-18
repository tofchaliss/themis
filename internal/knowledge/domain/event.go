package domain

import (
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Knowledge events are completed business facts published on an actual Faultline state
// change — never on the mere arrival of a Proposal (D8; DOM-0033). Payloads are thin
// (mirroring Evidence D6): consumers fetch detail via the read API.

// FaultlineCreated announces that a new card exists.
type FaultlineCreated struct {
	FaultlineID FaultlineID
	CVE         string
	OccurredAt  time.Time
}

// FaultlineEnriched announces that the enterprise view changed. It carries a coarse
// headline (severity + exploit signals) so Governance can re-evaluate (EDR-GOVERNANCE-01
// D6) without fetching the whole card.
type FaultlineEnriched struct {
	FaultlineID   FaultlineID
	CVE           string
	Severity      value.Severity
	KEV           bool
	ExploitPublic bool
	OccurredAt    time.Time
}

// FaultlineMatured announces the card reached the Mature stage.
type FaultlineMatured struct {
	FaultlineID FaultlineID
	CVE         string
	OccurredAt  time.Time
}

// FaultlineSuperseded announces the card reached the terminal Superseded stage.
type FaultlineSuperseded struct {
	FaultlineID FaultlineID
	CVE         string
	OccurredAt  time.Time
}

// MatchedComponent is one release component that matched a card during correlation.
type MatchedComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
}

// ComponentMatched is the correlation output (D3/D8): a release's component matches a
// card. Governance consumes it to create a Finding (EDR-GOVERNANCE-01 D5). It is a
// Proposal, not truth, and never mutates the card.
type ComponentMatched struct {
	FaultlineID FaultlineID
	CVE         string
	ReleaseID   string
	Components  []MatchedComponent
	OccurredAt  time.Time
}

// NewFaultlineCreated builds the event for a newly created card.
func NewFaultlineCreated(f Faultline, at time.Time) FaultlineCreated {
	return FaultlineCreated{FaultlineID: f.ID(), CVE: f.CVE().String(), OccurredAt: at.UTC()}
}

// NewFaultlineEnriched builds the view-change event, snapshotting the current headline.
func NewFaultlineEnriched(f Faultline, at time.Time) FaultlineEnriched {
	v := f.View()
	return FaultlineEnriched{
		FaultlineID:   f.ID(),
		CVE:           f.CVE().String(),
		Severity:      v.Severity,
		KEV:           v.KEV,
		ExploitPublic: v.ExploitPublic,
		OccurredAt:    at.UTC(),
	}
}

// NewFaultlineMatured builds the Mature-stage event.
func NewFaultlineMatured(f Faultline, at time.Time) FaultlineMatured {
	return FaultlineMatured{FaultlineID: f.ID(), CVE: f.CVE().String(), OccurredAt: at.UTC()}
}

// NewFaultlineSuperseded builds the Superseded-stage event.
func NewFaultlineSuperseded(f Faultline, at time.Time) FaultlineSuperseded {
	return FaultlineSuperseded{FaultlineID: f.ID(), CVE: f.CVE().String(), OccurredAt: at.UTC()}
}

// NewComponentMatched builds the correlation event for a release's matched components.
func NewComponentMatched(f Faultline, releaseID string, components []MatchedComponent, at time.Time) ComponentMatched {
	return ComponentMatched{
		FaultlineID: f.ID(),
		CVE:         f.CVE().String(),
		ReleaseID:   releaseID,
		Components:  append([]MatchedComponent(nil), components...),
		OccurredAt:  at.UTC(),
	}
}
