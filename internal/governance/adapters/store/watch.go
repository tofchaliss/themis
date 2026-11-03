package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The Watch store (EDR-INCIDENT-01 D2): the list of identifiers and the CVE set it last resolved
// to. No state about any Finding is stored here — the table is computed on read.

var _ app.WatchStore = (*Store)(nil)

// SaveWatch inserts or replaces the Watch whole.
func (s *Store) SaveWatch(ctx context.Context, w domain.Watch) error {
	var resolvedAt *time.Time
	if !w.ResolvedAt().IsZero() {
		t := w.ResolvedAt().UTC()
		resolvedAt = &t
	}
	identifiers, cves := w.Identifiers(), w.ResolvedCVEs()
	if identifiers == nil {
		identifiers = []string{}
	}
	if cves == nil {
		cves = []string{}
	}
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO watches (id, name, created_by, created_at, identifiers, resolved_cves, resolved_at, notify)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name, identifiers = EXCLUDED.identifiers,
			resolved_cves = EXCLUDED.resolved_cves, resolved_at = EXCLUDED.resolved_at, notify = EXCLUDED.notify`,
		w.ID(), w.Name(), w.CreatedBy(), w.CreatedAt().UTC(), identifiers, cves, resolvedAt, w.Notify())
	return err
}

const watchColumns = `id, name, created_by, created_at, identifiers, resolved_cves, resolved_at, notify`

func scanWatch(row pgx.Row) (domain.Watch, error) {
	var (
		id, name, createdBy string
		createdAt           time.Time
		identifiers, cves   []string
		resolvedAt          *time.Time
		notify              bool
	)
	if err := row.Scan(&id, &name, &createdBy, &createdAt, &identifiers, &cves, &resolvedAt, &notify); err != nil {
		return domain.Watch{}, err
	}
	var at time.Time
	if resolvedAt != nil {
		at = resolvedAt.UTC()
	}
	return domain.ReconstituteWatch(id, name, createdBy, createdAt.UTC(), identifiers, cves, at, notify), nil
}

// GetWatch loads one Watch; ErrNotFound when there is none.
func (s *Store) GetWatch(ctx context.Context, id string) (domain.Watch, error) {
	w, err := scanWatch(s.querier(ctx).QueryRow(ctx, `SELECT `+watchColumns+` FROM watches WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Watch{}, ErrNotFound
	}
	return w, err
}

// ListWatches lists every Watch, newest first.
func (s *Store) ListWatches(ctx context.Context) ([]domain.Watch, error) {
	rows, err := s.querier(ctx).Query(ctx, `SELECT `+watchColumns+` FROM watches ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Watch
	for rows.Next() {
		w, err := scanWatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// DeleteWatch removes a Watch whole; ErrNotFound when there was none.
func (s *Store) DeleteWatch(ctx context.Context, id string) error {
	tag, err := s.exec(ctx).Exec(ctx, `DELETE FROM watches WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
