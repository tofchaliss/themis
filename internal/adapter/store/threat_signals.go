package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresThreatSignalStore persists EPSS/KEV signals.
type PostgresThreatSignalStore struct {
	pool pgQueryPool
}

// NewPostgresThreatSignalStore creates a threat signal store.
func NewPostgresThreatSignalStore(pool pgQueryPool) *PostgresThreatSignalStore {
	return &PostgresThreatSignalStore{pool: pool}
}

func (s *PostgresThreatSignalStore) UpsertEPSS(ctx context.Context, signals []domain.EPSSSignal) error {
	if len(signals) == 0 {
		return nil
	}
	fetchedAt := signals[0].FetchedAt
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}
	for _, signal := range signals {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO epss_kev_signals (cve_id, epss_score, fetched_at, stale)
			VALUES ($1, $2, $3, FALSE)
			ON CONFLICT (cve_id) DO UPDATE SET
				epss_score = EXCLUDED.epss_score,
				fetched_at = EXCLUDED.fetched_at,
				stale = FALSE
		`, signal.CVEID, signal.Score, fetchedAt)
		if err != nil {
			return fmt.Errorf("upsert epss signal %s: %w", signal.CVEID, err)
		}
	}
	return nil
}

func (s *PostgresThreatSignalStore) UpsertKEV(ctx context.Context, signals []domain.KEVSignal) error {
	prevListed, err := s.ListKEVCVEIDs(ctx)
	if err != nil {
		return err
	}

	listed := make(map[string]struct{}, len(signals))
	fetchedAt := time.Now().UTC()
	for _, signal := range signals {
		if !signal.FetchedAt.IsZero() {
			fetchedAt = signal.FetchedAt
		}
		listed[signal.CVEID] = struct{}{}
		_, err := s.pool.Exec(ctx, `
			INSERT INTO epss_kev_signals (cve_id, kev_listed, fetched_at, stale)
			VALUES ($1, TRUE, $2, FALSE)
			ON CONFLICT (cve_id) DO UPDATE SET
				kev_listed = TRUE,
				fetched_at = EXCLUDED.fetched_at,
				stale = FALSE
		`, signal.CVEID, fetchedAt)
		if err != nil {
			return fmt.Errorf("upsert kev signal %s: %w", signal.CVEID, err)
		}
	}

	for _, cveID := range prevListed {
		if _, ok := listed[cveID]; ok {
			continue
		}
		_, err := s.pool.Exec(ctx, `
			UPDATE epss_kev_signals
			SET kev_listed = FALSE, fetched_at = $2, stale = FALSE
			WHERE cve_id = $1
		`, cveID, fetchedAt)
		if err != nil {
			return fmt.Errorf("clear kev signal %s: %w", cveID, err)
		}
	}
	return nil
}

func (s *PostgresThreatSignalStore) ListKEVCVEIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT cve_id FROM epss_kev_signals WHERE kev_listed = TRUE ORDER BY cve_id
	`)
	if err != nil {
		return nil, fmt.Errorf("list kev cve ids: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			return nil, err
		}
		out = append(out, cveID)
	}
	return out, rows.Err()
}

func (s *PostgresThreatSignalStore) MarkStale(ctx context.Context, stale bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE epss_kev_signals SET stale = $1`, stale)
	if err != nil {
		return fmt.Errorf("mark epss kev stale: %w", err)
	}
	return nil
}

func (s *PostgresThreatSignalStore) SignalsStale(ctx context.Context) (bool, error) {
	var stale bool
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(BOOL_OR(stale), FALSE) FROM epss_kev_signals
	`).Scan(&stale)
	if err != nil {
		return false, fmt.Errorf("query signals stale: %w", err)
	}
	if stale {
		return true, nil
	}
	last, err := s.LastSuccessfulFetch(ctx)
	if err != nil || last.IsZero() {
		return false, err
	}
	return time.Since(last) > 25*time.Hour, nil
}

func (s *PostgresThreatSignalStore) GetEPSSForCVE(ctx context.Context, cveID string) (*float64, error) {
	var score *float64
	err := s.pool.QueryRow(ctx, `
		SELECT epss_score FROM epss_kev_signals WHERE cve_id = $1
	`, cveID).Scan(&score)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get epss for cve: %w", err)
	}
	return score, nil
}

func (s *PostgresThreatSignalStore) IsKEVListed(ctx context.Context, cveID string) (bool, error) {
	var listed bool
	err := s.pool.QueryRow(ctx, `
		SELECT kev_listed FROM epss_kev_signals WHERE cve_id = $1
	`, cveID).Scan(&listed)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("get kev for cve: %w", err)
	}
	return listed, nil
}

func (s *PostgresThreatSignalStore) CountEPSSRows(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM epss_kev_signals WHERE epss_score IS NOT NULL
	`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count epss rows: %w", err)
	}
	return count, nil
}

func (s *PostgresThreatSignalStore) LastSuccessfulFetch(ctx context.Context) (time.Time, error) {
	var last time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(fetched_at), 'epoch'::timestamptz) FROM epss_kev_signals
	`).Scan(&last)
	if err != nil {
		return time.Time{}, fmt.Errorf("last successful fetch: %w", err)
	}
	if last.IsZero() || last.Unix() == 0 {
		return time.Time{}, nil
	}
	return last, nil
}
