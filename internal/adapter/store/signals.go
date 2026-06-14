package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresExploitStore persists ExploitDB records.
type PostgresExploitStore struct {
	pool pgQueryPool
}

// NewPostgresExploitStore creates an exploit record store.
func NewPostgresExploitStore(pool pgQueryPool) *PostgresExploitStore {
	return &PostgresExploitStore{pool: pool}
}

func (s *PostgresExploitStore) UpsertExploits(ctx context.Context, records []domain.ExploitRecord) error {
	for _, record := range records {
		var published any
		if record.PublishedDate != nil {
			published = *record.PublishedDate
		}
		cveID := nullIfEmpty(record.CVEID)
		_, err := s.pool.Exec(ctx, `
			INSERT INTO exploit_records (id, edb_id, cve_id, exploit_type, published_date, title)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (edb_id) DO UPDATE SET
				cve_id = EXCLUDED.cve_id,
				exploit_type = EXCLUDED.exploit_type,
				published_date = EXCLUDED.published_date,
				title = EXCLUDED.title
		`, uuid.NewString(), record.EDBID, cveID, nullIfEmpty(record.ExploitType), published, nullIfEmpty(record.Title))
		if err != nil {
			return fmt.Errorf("upsert exploit record %s: %w", record.EDBID, err)
		}
	}
	return nil
}

func (s *PostgresExploitStore) HasPublicExploit(ctx context.Context, cveID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM exploit_records WHERE cve_id = $1
		)
	`, cveID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has public exploit: %w", err)
	}
	return exists, nil
}

func (s *PostgresExploitStore) CountExploits(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM exploit_records`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count exploit records: %w", err)
	}
	return count, nil
}

// CombinedSignalReader loads EPSS/KEV and ExploitDB signals for re-enrichment.
type CombinedSignalReader struct {
	Threat  domain.ThreatSignalStore
	Exploit domain.ExploitStore
}

func (r CombinedSignalReader) GetEPSSForCVE(ctx context.Context, cveID string) (*float64, error) {
	if r.Threat == nil {
		return nil, nil
	}
	return r.Threat.GetEPSSForCVE(ctx, cveID)
}

func (r CombinedSignalReader) IsKEVListed(ctx context.Context, cveID string) (bool, error) {
	if r.Threat == nil {
		return false, nil
	}
	return r.Threat.IsKEVListed(ctx, cveID)
}

func (r CombinedSignalReader) HasPublicExploit(ctx context.Context, cveID string) (bool, error) {
	if r.Exploit == nil {
		return false, nil
	}
	return r.Exploit.HasPublicExploit(ctx, cveID)
}
