package store

import (
	"context"
	"time"
)

// RetireComponent marks one mirrored component row retired (KN-SCAN-4(b)).
//
// Like SetComponentVerdict it is denormalized read-data Knowledge owns — independent of the
// aggregate version — so it does not load, mutate or re-save the Finding. That is deliberate and
// it is the whole reason this needs no domain change: **a Position belongs to a Finding, not to a
// component**, so retiring a duplicate component retracts no security decision, and queue state
// re-derives from the components that remain.
//
// MARKED, never deleted. The row stays, so the audit trail keeps every observation Themis
// recorded and "we retired this" stays distinguishable from "this never happened" — the same
// reasoning that makes a cleared verdict recorded state rather than a deleted row, and that
// rejected DELETE for the 2026-09-10 repair.
//
// Idempotent, as the event contract requires: guarded on `retired_at IS NULL`, so re-delivery
// re-asserts the same state and changes nothing. A zero-row update is a NO-OP, not an error —
// the row may legitimately not exist yet (events can arrive out of order) or already be retired.
func (s *Store) RetireComponent(ctx context.Context, releaseID, faultlineID, purl, reason string, at time.Time) error {
	_, err := s.exec(ctx).Exec(ctx, `
		UPDATE finding_components c
		SET retired_at = $5, retired_reason = $4
		FROM findings f
		WHERE c.finding_id = f.id AND f.release_id = $1 AND f.faultline_id = $2
		  AND c.purl = $3 AND c.retired_at IS NULL`,
		releaseID, faultlineID, purl, reason, at.UTC())
	return err
}
