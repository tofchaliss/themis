package domain

import "time"

// Communication events are thin, terminal completed facts (DOM-0033 / D8), published after
// persist via the shared outbox. They announce that a materialization/delivery fact occurred
// and establish NO new truth (CON-0010). They are consumed only by the audit log / metrics /
// (optionally) external integrations — never by an upstream context (CON-0001, one-way flow).

// PublicationCreated announces a new immutable Publication was recorded.
type PublicationCreated struct {
	PublicationID PublicationID
	Type          ArtifactType
	Stance        Stance
	ReleaseID     string
	FaultlineID   string
	CVE           string
	OccurredAt    time.Time
}

// PublicationDelivered announces a Publication's artifact was delivered on its channel.
type PublicationDelivered struct {
	PublicationID PublicationID
	Channel       string
	OccurredAt    time.Time
}

// PublicationSuperseded announces a Publication was replaced by a newer one after a Position
// revision (both records are kept — D5).
type PublicationSuperseded struct {
	PublicationID  PublicationID
	SupersededByID PublicationID
	OccurredAt     time.Time
}

// NewPublicationCreated builds the event for a newly recorded Publication.
func NewPublicationCreated(p Publication, at time.Time) PublicationCreated {
	l := p.Lineage()
	return PublicationCreated{
		PublicationID: p.ID(),
		Type:          p.Type(),
		Stance:        p.Stance(),
		ReleaseID:     l.ReleaseID,
		FaultlineID:   l.FaultlineID,
		CVE:           l.CVE,
		OccurredAt:    at.UTC(),
	}
}

// NewPublicationDelivered builds the event for a delivered Publication.
func NewPublicationDelivered(p Publication, at time.Time) PublicationDelivered {
	return PublicationDelivered{PublicationID: p.ID(), Channel: p.Channel(), OccurredAt: at.UTC()}
}

// NewPublicationSuperseded builds the event for a superseded Publication.
func NewPublicationSuperseded(p Publication, at time.Time) PublicationSuperseded {
	return PublicationSuperseded{PublicationID: p.ID(), SupersededByID: p.SupersededBy(), OccurredAt: at.UTC()}
}
