package store

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// AnnounceCorrelationCompleted queues the once-per-SBOM completion event
// (EDR-DELIVERY-01 M2-1 / M2a-3, N-M2a). Called at the END of ApplyCorrelation's unit of work,
// so it joins the inbox transaction when one rides the context — the completion fact and the
// matches it concludes commit or roll back together, and a rolled-back correlation announces
// nothing.
//
// The subject is the RELEASE, not a Faultline: this is the only Knowledge event that is about
// an SBOM rather than a card, and a consumer reads it as "there is nothing more coming for this
// SBOM".
//
// ORDERING is why this event exists, and it rests on two things, both local to this SBOM's
// correlation: the row is appended LAST in the unit of work, carrying the caller's timestamp —
// which is read after every other note of that correlation was stamped — and the relay sorts the
// completion last within a shared instant (see DeliverPending), so a frozen or coarse clock
// stamping a whole unit of work alike cannot reorder it. Nothing here consults other SBOMs'
// rows: the promise is per SBOM, and a timestamp derived from the whole outbox would reorder
// unrelated events and could still tie between two concurrent transactions.
func (s *Store) AnnounceCorrelationCompleted(ctx context.Context, releaseID, sbomID, cause string, at time.Time) error {
	tx, own, err := s.beginOrJoin(ctx)
	if err != nil {
		return err
	}
	if own {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	// One timestamp for the row and for the body, so the envelope and the payload cannot
	// disagree about when this happened. Rounded to the microsecond because that is what a
	// timestamptz column keeps (PostgreSQL rounds, it does not truncate): an unrounded
	// nanosecond clock would leave the body more precise than the stored envelope. Rounding is
	// monotone, so it cannot move the completion before a note of its own run.
	occurredAt := at.UTC().Round(time.Microsecond)
	ev := domain.NewReleaseCorrelationCompleted(releaseID, sbomID, cause, occurredAt)
	if err := s.queueOutbox(ctx, tx, app.EventReleaseCorrelationCompleted, releaseID, ev, occurredAt); err != nil {
		return err
	}

	if own {
		return tx.Commit(ctx)
	}
	return nil // the inbox unit of work owns the commit
}
