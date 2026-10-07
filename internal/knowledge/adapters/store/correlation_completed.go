package store

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// AnnounceCorrelationCompleted queues the once-per-SBOM completion event
// (EDR-DELIVERY-01 M2-1, N-M2a). Called at the END of ApplyCorrelation's unit of work, so it
// joins the inbox transaction when one rides the context — the completion fact and the matches
// it concludes commit or roll back together, and a rolled-back correlation announces nothing.
//
// The subject is the RELEASE, not a Faultline: this is the only Knowledge event that is about
// an SBOM rather than a card, and a consumer reads it as "there is nothing more coming for this
// SBOM".
//
// ORDERING is the whole point of this event, so it is made a property of the WRITE rather than
// of the clock. The relay delivers outbox rows `ORDER BY occurred_at` and the bus assigns `seq`
// in append order, so "appended after every other event for this SBOM" means exactly "carries a
// strictly greater occurred_at than any event still undelivered". The outbox has no sequence
// column to lean on, and taking the caller's timestamp on trust would be a tie wherever the
// clock is coarse or frozen (every fold note and match note in one correlation can share a
// timestamp) — and a tie leaves the relay's order undefined, which is precisely the ordering
// this event exists to guarantee. One in-transaction MAX over the unsent rows (served by the
// partial index on occurred_at) settles it; the same timestamp goes on the row and in the body,
// so the envelope and the payload cannot disagree about when this happened.
func (s *Store) AnnounceCorrelationCompleted(ctx context.Context, releaseID, sbomID, cause string, at time.Time) error {
	tx, own, err := s.beginOrJoin(ctx)
	if err != nil {
		return err
	}
	if own {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	orderedAt := at.UTC()
	if err := tx.QueryRow(ctx, `
		SELECT GREATEST($1::timestamptz,
		                COALESCE(MAX(occurred_at) + INTERVAL '1 microsecond', $1::timestamptz))
		FROM knowledge_outbox WHERE sent_at IS NULL`, orderedAt).Scan(&orderedAt); err != nil {
		return err
	}

	ev := domain.NewReleaseCorrelationCompleted(releaseID, sbomID, cause, orderedAt)
	if err := s.queueOutbox(ctx, tx, app.EventReleaseCorrelationCompleted, releaseID, ev, orderedAt); err != nil {
		return err
	}

	if own {
		return tx.Commit(ctx)
	}
	return nil // the inbox unit of work owns the commit
}
