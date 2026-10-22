package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// The webhook channel's tables (EDR-REMEDIATION-01 D4): destination health and the SLA digest.

var (
	_ app.WebhookHealthStore = (*Store)(nil)
	_ app.SLADigestStore     = (*Store)(nil)
)

const webhookHealthColumns = `destination, state, consecutive_failures, pauses, paused_until,
	last_success_at, last_failure_at, last_error`

func scanWebhookHealth(row pgx.Row) (domain.WebhookHealth, error) {
	var (
		h                   domain.WebhookHealth
		state               string
		paused, succ, failed *time.Time
	)
	if err := row.Scan(&h.Destination, &state, &h.ConsecutiveFailures, &h.Pauses, &paused, &succ, &failed, &h.LastError); err != nil {
		return domain.WebhookHealth{}, err
	}
	h.State = domain.WebhookHealthState(state)
	h.PausedUntil, h.LastSuccessAt, h.LastFailureAt = deref(paused), deref(succ), deref(failed)
	return h, nil
}

func deref(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func nullable(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// WebhookHealth returns a destination's health; one never recorded reads active.
func (s *Store) WebhookHealth(ctx context.Context, destination string) (domain.WebhookHealth, error) {
	h, err := scanWebhookHealth(s.pool.QueryRow(ctx,
		`SELECT `+webhookHealthColumns+` FROM webhook_health WHERE destination = $1`, destination))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NewWebhookHealth(destination), nil
	}
	return h, err
}

// SaveWebhookHealth upserts a destination's health.
func (s *Store) SaveWebhookHealth(ctx context.Context, h domain.WebhookHealth, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO webhook_health (destination, state, consecutive_failures, pauses, paused_until,
		                            last_success_at, last_failure_at, last_error, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (destination) DO UPDATE SET
		    state = EXCLUDED.state, consecutive_failures = EXCLUDED.consecutive_failures,
		    pauses = EXCLUDED.pauses, paused_until = EXCLUDED.paused_until,
		    last_success_at = EXCLUDED.last_success_at, last_failure_at = EXCLUDED.last_failure_at,
		    last_error = EXCLUDED.last_error, updated_at = EXCLUDED.updated_at`,
		h.Destination, string(h.State), h.ConsecutiveFailures, h.Pauses, nullable(h.PausedUntil),
		nullable(h.LastSuccessAt), nullable(h.LastFailureAt), h.LastError, at)
	return err
}

// ListWebhookHealth returns every recorded destination, by name.
func (s *Store) ListWebhookHealth(ctx context.Context) ([]domain.WebhookHealth, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+webhookHealthColumns+` FROM webhook_health ORDER BY destination`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.WebhookHealth
	for rows.Next() {
		h, err := scanWebhookHealth(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RecordSLABreach stores one breach for the digest, once per (finding, period). It joins the
// inbox transaction when the reader calls it.
func (s *Store) RecordSLABreach(ctx context.Context, r app.SLABreachRecord) error {
	_, err := s.q(ctx).Exec(ctx, `
		INSERT INTO sla_breach_digest (finding_id, period_start, release_id, cve, bucket, due, recorded_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (finding_id, period_start) DO NOTHING`,
		r.FindingID, r.PeriodStart, r.ReleaseID, r.CVE, r.Bucket, r.Due, r.RecordedAt)
	return err
}

// PendingSLABreaches returns the breaches not yet sent in a digest, oldest first.
func (s *Store) PendingSLABreaches(ctx context.Context) ([]app.SLABreachRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT finding_id, period_start, release_id, cve, bucket, due, recorded_at
		FROM sla_breach_digest WHERE digest_id IS NULL ORDER BY recorded_at, finding_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.SLABreachRecord
	for rows.Next() {
		var r app.SLABreachRecord
		if err := rows.Scan(&r.FindingID, &r.PeriodStart, &r.ReleaseID, &r.CVE, &r.Bucket, &r.Due, &r.RecordedAt); err != nil {
			return nil, err
		}
		r.PeriodStart, r.Due, r.RecordedAt = r.PeriodStart.UTC(), r.Due.UTC(), r.RecordedAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkSLABreachesDigested stamps the sent rows with their digest.
func (s *Store) MarkSLABreachesDigested(ctx context.Context, keys []app.SLABreachRecord, digestID string) error {
	for _, k := range keys {
		if _, err := s.pool.Exec(ctx,
			`UPDATE sla_breach_digest SET digest_id = $3 WHERE finding_id = $1 AND period_start = $2 AND digest_id IS NULL`,
			k.FindingID, k.PeriodStart, digestID); err != nil {
			return err
		}
	}
	return nil
}
