package queue

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresJobStore persists ingestion jobs in PostgreSQL.
type PostgresJobStore struct {
	pool *pgxpool.Pool
}

// NewPostgresJobStore creates a store backed by ingestion_jobs.
func NewPostgresJobStore(pool *pgxpool.Pool) *PostgresJobStore {
	return &PostgresJobStore{pool: pool}
}

func (s *PostgresJobStore) Create(ctx context.Context, jobID, jobType string, payload []byte) (string, error) {
	id := jobID
	if id == "" {
		id = uuid.NewString()
	}
	if len(payload) == 0 {
		payload = []byte("{}")
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO ingestion_jobs (id, job_type, status, payload)
		VALUES ($1, $2, 'pending', $3::jsonb)
	`, id, jobType, payload)
	if err != nil {
		return "", fmt.Errorf("insert ingestion job: %w", err)
	}
	return id, nil
}

func (s *PostgresJobStore) MarkRunning(ctx context.Context, jobID string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE ingestion_jobs
		SET status = 'running',
		    started_at = COALESCE(started_at, NOW())
		WHERE id = $1
	`, jobID)
	if err != nil {
		return fmt.Errorf("mark job running: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("job %q not found", jobID)
	}
	return nil
}

func (s *PostgresJobStore) MarkCompleted(ctx context.Context, jobID string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE ingestion_jobs
		SET status = 'completed',
		    completed_at = NOW(),
		    error_message = NULL
		WHERE id = $1
	`, jobID)
	if err != nil {
		return fmt.Errorf("mark job completed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("job %q not found", jobID)
	}
	return nil
}

func (s *PostgresJobStore) MarkFailed(ctx context.Context, jobID, message string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE ingestion_jobs
		SET status = 'failed',
		    completed_at = NOW(),
		    error_message = $2
		WHERE id = $1
	`, jobID, message)
	if err != nil {
		return fmt.Errorf("mark job failed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("job %q not found", jobID)
	}
	return nil
}

func (s *PostgresJobStore) IncrementAttempts(ctx context.Context, jobID string) (int, error) {
	var attempts int
	err := s.pool.QueryRow(ctx, `
		UPDATE ingestion_jobs
		SET attempts = attempts + 1
		WHERE id = $1
		RETURNING attempts
	`, jobID).Scan(&attempts)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, fmt.Errorf("job %q not found", jobID)
		}
		return 0, fmt.Errorf("increment job attempts: %w", err)
	}
	return attempts, nil
}

func (s *PostgresJobStore) CountByStatus(ctx context.Context, status string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM ingestion_jobs
		WHERE status = $1
	`, status).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count jobs by status: %w", err)
	}
	return count, nil
}

func (s *PostgresJobStore) GetAttempts(ctx context.Context, jobID string) (int, error) {
	var attempts int
	err := s.pool.QueryRow(ctx, `
		SELECT attempts
		FROM ingestion_jobs
		WHERE id = $1
	`, jobID).Scan(&attempts)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, fmt.Errorf("job %q not found", jobID)
		}
		return 0, fmt.Errorf("get job attempts: %w", err)
	}
	return attempts, nil
}
