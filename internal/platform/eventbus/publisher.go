package eventbus

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
)

// Publisher appends kernel Envelopes to the bus event_log — the outbound half of the
// platform transport (EB-04 · D1/D2/D4). A context's relay drains its transactional
// outbox and calls Publish for each unsent row; on success the relay marks the row sent
// (BCK-0041 durability: the outbox row survives until the append is confirmed).
//
// Delivery is at-least-once: if the relay crashes after a successful append but before
// marking the row sent, it re-delivers, so Publish MUST be idempotent. The UNIQUE
// envelope_id + ON CONFLICT DO NOTHING gives at-most-once append (D5), so a redelivery
// adds no duplicate log row — exactly one row per distinct envelope.
type Publisher struct {
	pool *pgxpool.Pool
}

// NewPublisher builds a Publisher over a pool connected to the `bus` database.
func NewPublisher(pool *pgxpool.Pool) *Publisher { return &Publisher{pool: pool} }

// insertEnvelopeSQL is built from the event_log column constants (bus.go) — the one
// source of truth shared with the migrations and the Reader — so a schema change is made
// in one place. seq is assigned by the BIGSERIAL default; the append is idempotent on
// envelope_id.
var insertEnvelopeSQL = fmt.Sprintf(
	`INSERT INTO %s (%s, %s, %s, %s, %s, %s, %s, %s)
	 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	 ON CONFLICT (%s) DO NOTHING`,
	TableEventLog,
	ColEnvelopeID, ColSourceContext, ColSubject, ColType, ColOccurredAt, ColCorrelationID, ColSchemaRef, ColPayload,
	ColEnvelopeID,
)

// Publish appends one envelope to the event log. It is idempotent: re-publishing an
// envelope already in the log is a no-op that returns nil.
func (p *Publisher) Publish(ctx context.Context, env event.Envelope) error {
	// pgx encodes []byte as bytea, so a JSONB column needs the payload as a string; a
	// thin event with no payload is stored as SQL NULL.
	var payload any
	if len(env.Payload) > 0 {
		payload = string(env.Payload)
	}
	if _, err := p.pool.Exec(ctx, insertEnvelopeSQL,
		env.ID, env.SourceContext, env.Subject, env.Type, env.OccurredAt, env.CorrelationID, env.SchemaRef, payload,
	); err != nil {
		return fmt.Errorf("eventbus: append envelope %s: %w", env.ID, err)
	}
	return nil
}
