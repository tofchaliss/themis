package domain

import (
	"errors"
	"time"
)

// RollupPublication is the immutable record of one published release-scoped VEX rollup
// (D13). It is deliberately its OWN record type, not a Publication: the Publication
// aggregate's hard invariant is stance-equality with ONE Position (D3), and a rollup has no
// single stance — it is a materialized POSTURE snapshot, not a materialized Position.
// Bending Publication's validation to admit it would weaken the invariant for every
// per-Finding artifact to accommodate one document.
//
// It shares Publication's revision discipline (D5): append-and-supersede, both kept,
// "current" = latest non-superseded per (release, format, audience). Delivery via channels
// is deliberately NOT wired for rollups yet — recorded in COMM-VEX-1's tasks, alongside
// rollup outbox events, as the follow-up the delivery worker needs.
type RollupPublication struct {
	id                RollupPublicationID
	releaseID         string
	productPURL       string
	format            string
	audience          string
	payload           []byte
	inputSet          []RollupInputRecord
	asOf              time.Time
	statements        int
	withdrawnExcluded int
	supersedes        RollupPublicationID
	supersededBy      RollupPublicationID
	version           int
	createdAt         time.Time
}

// RollupPublicationID is a rollup publication's opaque identity.
type RollupPublicationID string

var (
	errEmptyRollupID      = errors.New("communication: empty rollup publication id")
	errEmptyRollupPayload = errors.New("communication: empty rollup payload")
)

// NewRollupPublication records a freshly materialized rollup.
func NewRollupPublication(id RollupPublicationID, art RollupArtifact, format, audience string, payload []byte, supersedes RollupPublicationID, at time.Time) (RollupPublication, error) {
	if id == "" {
		return RollupPublication{}, errEmptyRollupID
	}
	if !art.Product.Complete() {
		return RollupPublication{}, errIncompleteProduct
	}
	if format == "" {
		return RollupPublication{}, errEmptyFormat
	}
	if len(payload) == 0 {
		return RollupPublication{}, errEmptyRollupPayload
	}
	return RollupPublication{
		id: id, releaseID: art.Product.ReleaseID, productPURL: art.Product.PURL(),
		format: format, audience: audience, payload: append([]byte(nil), payload...),
		inputSet: append([]RollupInputRecord(nil), art.InputSet...),
		asOf:     art.AsOf, statements: len(art.Statements), withdrawnExcluded: art.WithdrawnExcluded,
		supersedes: supersedes, version: 1, createdAt: at.UTC(),
	}, nil
}

// Supersede links this rollup to its successor — set once, append-and-supersede (D5).
func (r *RollupPublication) Supersede(by RollupPublicationID) error {
	if r.supersededBy != "" {
		return ErrAlreadySuperseded
	}
	r.supersededBy = by
	r.version++
	return nil
}

// Accessors (immutable content; version guards optimistic concurrency).
func (r RollupPublication) ID() RollupPublicationID           { return r.id }
func (r RollupPublication) ReleaseID() string                 { return r.releaseID }
func (r RollupPublication) ProductPURL() string               { return r.productPURL }
func (r RollupPublication) Format() string                    { return r.format }
func (r RollupPublication) Audience() string                  { return r.audience }
func (r RollupPublication) Payload() []byte                   { return append([]byte(nil), r.payload...) }
func (r RollupPublication) InputSet() []RollupInputRecord     { return append([]RollupInputRecord(nil), r.inputSet...) }
func (r RollupPublication) AsOf() time.Time                   { return r.asOf }
func (r RollupPublication) Statements() int                   { return r.statements }
func (r RollupPublication) WithdrawnExcluded() int            { return r.withdrawnExcluded }
func (r RollupPublication) Supersedes() RollupPublicationID   { return r.supersedes }
func (r RollupPublication) SupersededBy() RollupPublicationID { return r.supersededBy }
func (r RollupPublication) Version() int                      { return r.version }
func (r RollupPublication) CreatedAt() time.Time              { return r.createdAt }

// ReconstituteRollupPublication rebuilds the record from storage (adapters only).
func ReconstituteRollupPublication(id RollupPublicationID, releaseID, productPURL, format, audience string,
	payload []byte, inputSet []RollupInputRecord, asOf time.Time, statements, withdrawnExcluded int,
	supersedes, supersededBy RollupPublicationID, version int, createdAt time.Time) RollupPublication {
	return RollupPublication{
		id: id, releaseID: releaseID, productPURL: productPURL, format: format, audience: audience,
		payload: payload, inputSet: inputSet, asOf: asOf, statements: statements,
		withdrawnExcluded: withdrawnExcluded, supersedes: supersedes, supersededBy: supersededBy,
		version: version, createdAt: createdAt,
	}
}
