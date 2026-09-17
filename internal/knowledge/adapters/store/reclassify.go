package store

import (
	"context"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// Re-classification queries (EDR-CORRELATION-01 D3/D4, KN-CLAIM-1). Like the D6 verdict stamp,
// the stamp comparison IS the queue — there is no separate list to maintain, so nothing can go
// stale beside the stamps themselves. Unlike D6 the stamps sit on the CARD, because Knowledge
// persists no claim class and the input that changes is the card's carrier set.

// StaleClassificationCards returns up to limit cards whose re-classification stamps lag, either
// behind the card's own version (its carriers may have moved) or behind the current rule
// generation (the rules themselves changed). Cards with no recorded matches are excluded —
// there is nothing to re-announce for them and including them would spend the batch on no-ops.
//
// Ordered by the stamps so a bounded batch makes forward progress: a just-stamped card sorts
// behind everything still unstamped, which is what lets consecutive sweeps drain history rather
// than re-reading one head. Implements app.StaleClassificationSource.
func (s *Store) StaleClassificationCards(ctx context.Context, generation, limit int) ([]app.StaleCard, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT f.id, f.version
		FROM faultlines f
		WHERE (f.reclassified_generation < $1 OR f.reclassified_version < f.version)
		  AND EXISTS (SELECT 1 FROM faultline_matches m WHERE m.faultline_id = f.id)
		ORDER BY f.reclassified_generation, f.reclassified_version, f.id
		LIMIT $2`, generation, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []app.StaleCard
	for rows.Next() {
		var c app.StaleCard
		var id string
		if err := rows.Scan(&id, &c.Version); err != nil {
			return nil, err
		}
		c.ID = domain.FaultlineID(id)
		out = append(out, c)
	}
	return out, rows.Err()
}

// StampReclassified queues the re-announcement notes and advances the card's stamps in ONE
// transaction. Atomicity is the point: a card stamped current with nothing emitted would be
// skipped by every later sweep, turning the safety net into a permanent false negative.
//
// It deliberately touches neither `version` nor `updated_at`. Bumping the version would make
// every sweep look like a card change — to the re-verdict sweep, to the optimistic-concurrency
// guard, and to this sweep's own selector, which would then never converge.
// Implements app.ClassificationStamper.
func (s *Store) StampReclassified(ctx context.Context, id domain.FaultlineID,
	version, generation int, notes []app.OutboxNote) error {
	tx, own, err := s.beginOrJoin(ctx)
	if err != nil {
		return err
	}
	if own {
		defer func() { _ = tx.Rollback(ctx) }()
	}
	for _, n := range notes {
		if qerr := s.queueOutbox(ctx, tx, n.EventType, string(id), n.Event, n.OccurredAt); qerr != nil {
			return qerr
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE faultlines SET reclassified_version = $2, reclassified_generation = $3
		WHERE id = $1`, string(id), version, generation); err != nil {
		return err
	}
	if own {
		return tx.Commit(ctx)
	}
	return nil
}
