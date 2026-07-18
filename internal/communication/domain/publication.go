package domain

import "time"

// PublicationID is a Publication's own opaque, stable identity (provenance, not a business
// key — each materialized artifact is an independent immutable record).
type PublicationID string

// DeliveryStatus is the delivery lifecycle of a Publication's artifact (D6): the only
// mutable part of the aggregate.
type DeliveryStatus string

const (
	DeliveryPending   DeliveryStatus = "pending"
	DeliveryDelivered DeliveryStatus = "delivered"
	DeliveryFailed    DeliveryStatus = "failed"
)

// DeliveryOutcome records the delivery result on the Publication for traceability (CON-0016).
type DeliveryOutcome struct {
	Status      DeliveryStatus
	Attempts    int
	LastError   string
	DeliveredAt time.Time // zero until delivered
}

// Publication is Communication's immutable record of one materialized artifact from one
// Enterprise Position version (D1/D9) — the aggregate root and consistency boundary. Its
// content (artifact, format, audience/channel, payload, lineage, supersedes link) is fixed
// at creation and never edited; only the delivery outcome and the superseded-by link mutate,
// guarded by an optimistic version. Each Publication is its own aggregate, related to others
// only by supersession links (D5); "current" is a query (latest non-superseded), not parent
// state.
type Publication struct {
	id           PublicationID
	artifact     Artifact
	format       string
	audience     string
	channel      string
	payload      []byte // capped, regenerable materialized bytes (may be nil once pruned — D1)
	delivery     DeliveryOutcome
	supersedes   PublicationID
	supersededBy PublicationID
	version      int
	createdAt    time.Time
}

// NewPublication records a freshly materialized artifact as an immutable Publication in the
// Pending delivery state (D1). supersedes is the prior Publication this one replaces (empty
// for a first publication — D5).
func NewPublication(id PublicationID, artifact Artifact, format, audience, channel string, payload []byte, supersedes PublicationID, at time.Time) (Publication, error) {
	if id == "" {
		return Publication{}, errEmptyPublicationID
	}
	if !artifact.Type.Valid() {
		return Publication{}, errUnknownArtifact
	}
	if !artifact.Stance.Valid() {
		return Publication{}, errInvalidStance
	}
	if format == "" {
		return Publication{}, errEmptyFormat
	}
	return Publication{
		id:         id,
		artifact:   artifact,
		format:     format,
		audience:   audience,
		channel:    channel,
		payload:    append([]byte(nil), payload...),
		delivery:   DeliveryOutcome{Status: DeliveryPending},
		supersedes: supersedes,
		version:    1,
		createdAt:  at.UTC(),
	}, nil
}

// ReconstitutePublication rebuilds a Publication from persisted state (store adapter).
// Persistence is trusted; no re-validation is performed.
func ReconstitutePublication(id PublicationID, artifact Artifact, format, audience, channel string, payload []byte, delivery DeliveryOutcome, supersedes, supersededBy PublicationID, version int, createdAt time.Time) Publication {
	return Publication{
		id:           id,
		artifact:     artifact,
		format:       format,
		audience:     audience,
		channel:      channel,
		payload:      append([]byte(nil), payload...),
		delivery:     delivery,
		supersedes:   supersedes,
		supersededBy: supersededBy,
		version:      version,
		createdAt:    createdAt.UTC(),
	}
}

// MarkDelivered records a successful delivery (D6). Idempotent: delivering an
// already-delivered Publication is a no-op. Returns whether the state changed.
func (p *Publication) MarkDelivered(at time.Time) bool {
	if p.delivery.Status == DeliveryDelivered {
		return false
	}
	p.delivery.Status = DeliveryDelivered
	p.delivery.DeliveredAt = at.UTC()
	p.delivery.LastError = ""
	p.version++
	return true
}

// MarkFailed records a failed delivery attempt (D6); the delivery worker retries on the next
// pass. It increments the attempt count and records the error.
func (p *Publication) MarkFailed(reason string) {
	p.delivery.Status = DeliveryFailed
	p.delivery.Attempts++
	p.delivery.LastError = reason
	p.version++
}

// Supersede links this Publication to the newer one that replaces it after a Position
// revision (D5) — append-and-supersede, set once. Both records are kept; this one is no
// longer "current". Returns ErrAlreadySuperseded if a successor is already recorded.
func (p *Publication) Supersede(by PublicationID) error {
	if p.supersededBy != "" {
		return ErrAlreadySuperseded
	}
	p.supersededBy = by
	p.version++
	return nil
}

// PrunePayload drops the heavy rendered payload bytes past the retention cap (D1); the
// lineage metadata stays permanent and the payload is regenerable from the Position version
// + serializer. Returns whether payload was present to prune.
func (p *Publication) PrunePayload() bool {
	if p.payload == nil {
		return false
	}
	p.payload = nil
	p.version++
	return true
}

// ID returns the Publication's stable identity.
func (p Publication) ID() PublicationID { return p.id }

// Artifact returns the immutable materialized artifact content.
func (p Publication) Artifact() Artifact { return p.artifact }

// Stance returns the carried Position stance (equal to the artifact's stance — D3).
func (p Publication) Stance() Stance { return p.artifact.Stance }

// Type returns the artifact type.
func (p Publication) Type() ArtifactType { return p.artifact.Type }

// Format returns the serialization format the payload was rendered in.
func (p Publication) Format() string { return p.format }

// Audience returns the intended audience.
func (p Publication) Audience() string { return p.audience }

// Channel returns the delivery channel.
func (p Publication) Channel() string { return p.channel }

// Payload returns a copy of the rendered bytes, or nil if pruned (regenerable — D1).
func (p Publication) Payload() []byte {
	if p.payload == nil {
		return nil
	}
	return append([]byte(nil), p.payload...)
}

// PayloadPruned reports whether the payload has been pruned and must be regenerated on read.
func (p Publication) PayloadPruned() bool { return p.payload == nil }

// Delivery returns the current delivery outcome.
func (p Publication) Delivery() DeliveryOutcome { return p.delivery }

// Lineage returns the permanent reference chain.
func (p Publication) Lineage() Lineage { return p.artifact.Lineage }

// Supersedes returns the prior Publication this one replaced (empty if first).
func (p Publication) Supersedes() PublicationID { return p.supersedes }

// SupersededBy returns the newer Publication that replaced this one (empty if current).
func (p Publication) SupersededBy() PublicationID { return p.supersededBy }

// IsSuperseded reports whether a newer Publication has replaced this one.
func (p Publication) IsSuperseded() bool { return p.supersededBy != "" }

// Version returns the optimistic-concurrency version stamp.
func (p Publication) Version() int { return p.version }

// CreatedAt returns when the Publication was recorded.
func (p Publication) CreatedAt() time.Time { return p.createdAt }
