package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

type ingestionPayload struct {
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	PipelineStatus string `json:"pipeline_status"`
	StageDetail    string `json:"stage_detail,omitempty"`
	ScanID         string `json:"scan_id,omitempty"`
}

// PostgresIngestionRepository persists ingestion lifecycle metadata in ingestion_jobs.
type PostgresIngestionRepository struct {
	pool pgPool
}

// NewPostgresIngestionRepository creates a PostgreSQL ingestion repository.
func NewPostgresIngestionRepository(pool pgPool) *PostgresIngestionRepository {
	return &PostgresIngestionRepository{pool: pool}
}

func (r *PostgresIngestionRepository) FindByIdempotencyKey(ctx context.Context, key string) (domain.IngestionRecord, bool, error) {
	var id, jobType, status string
	var payloadBytes []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, job_type, status, payload
		FROM ingestion_jobs
		WHERE payload->>'idempotency_key' = $1
		   OR payload->'Input'->>'IdempotencyKey' = $1
		ORDER BY created_at DESC
		LIMIT 1
	`, key).Scan(&id, &jobType, &status, &payloadBytes)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.IngestionRecord{}, false, nil
		}
		return domain.IngestionRecord{}, false, fmt.Errorf("find ingestion by idempotency key: %w", err)
	}
	record, err := decodeIngestionRecord(id, jobType, status, payloadBytes)
	if err != nil {
		return domain.IngestionRecord{}, false, err
	}
	return record, true, nil
}

func (r *PostgresIngestionRepository) Create(ctx context.Context, record domain.IngestionRecord) error {
	if record.ID == "" {
		record.ID = uuid.NewString()
	}
	payload, err := encodeIngestionPayload(record)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO ingestion_jobs (id, job_type, status, payload)
		VALUES ($1, $2, 'running', $3::jsonb)
	`, record.ID, string(record.JobType), payload)
	if err != nil {
		return fmt.Errorf("create ingestion job: %w", err)
	}
	return nil
}

func (r *PostgresIngestionRepository) UpdateStatus(ctx context.Context, id string, status domain.IngestionStatus, detail, scanID string) error {
	current, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	current.Status = status
	current.StageDetail = detail
	if scanID != "" {
		current.ScanID = scanID
	}
	payload, err := encodeIngestionPayload(current)
	if err != nil {
		return err
	}
	jobStatus := mapPipelineToJobStatus(status)
	_, err = r.pool.Exec(ctx, `
		UPDATE ingestion_jobs
		SET status = $2,
		    payload = $3::jsonb,
		    error_message = $4,
		    completed_at = CASE WHEN $2 IN ('completed', 'failed', 'cancelled') THEN NOW() ELSE completed_at END
		WHERE id = $1
	`, id, jobStatus, payload, errorMessageForStatus(status, detail))
	if err != nil {
		return fmt.Errorf("update ingestion job: %w", err)
	}
	return nil
}

func (r *PostgresIngestionRepository) Get(ctx context.Context, id string) (domain.IngestionRecord, error) {
	var jobType, status string
	var payloadBytes []byte
	var createdAt time.Time
	var startedAt, completedAt *time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT job_type, status, payload, created_at, started_at, completed_at
		FROM ingestion_jobs
		WHERE id = $1
	`, id).Scan(&jobType, &status, &payloadBytes, &createdAt, &startedAt, &completedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.IngestionRecord{}, fmt.Errorf("ingestion %q not found", id)
		}
		return domain.IngestionRecord{}, fmt.Errorf("get ingestion job: %w", err)
	}
	record, err := decodeIngestionRecord(id, jobType, status, payloadBytes)
	if err != nil {
		return domain.IngestionRecord{}, err
	}
	record.CreatedAt = firstTime(startedAt, &createdAt)
	record.UpdatedAt = firstTime(completedAt, startedAt, &createdAt)
	return record, nil
}

// firstTime returns the first non-nil, non-zero time from candidates.
func firstTime(candidates ...*time.Time) time.Time {
	for _, c := range candidates {
		if c != nil && !c.IsZero() {
			return *c
		}
	}
	return time.Time{}
}

func encodeIngestionPayload(record domain.IngestionRecord) ([]byte, error) {
	payload := ingestionPayload{
		IdempotencyKey: record.IdempotencyKey,
		PipelineStatus: string(record.Status),
		StageDetail:    record.StageDetail,
		ScanID:         record.ScanID,
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal ingestion payload: %w", err)
	}
	return out, nil
}

func decodeIngestionRecord(id, jobType, jobStatus string, payloadBytes []byte) (domain.IngestionRecord, error) {
	var payload ingestionPayload
	if len(payloadBytes) > 0 {
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			return domain.IngestionRecord{}, fmt.Errorf("unmarshal ingestion payload: %w", err)
		}
		if payload.IdempotencyKey == "" {
			var queuePayload struct {
				Input struct {
					IdempotencyKey string `json:"IdempotencyKey"`
				} `json:"Input"`
			}
			if err := json.Unmarshal(payloadBytes, &queuePayload); err == nil {
				payload.IdempotencyKey = queuePayload.Input.IdempotencyKey
			}
		}
	}
	status := domain.IngestionStatus(payload.PipelineStatus)
	if status == "" {
		status = mapJobToPipelineStatus(jobStatus)
	}
	return domain.IngestionRecord{
		ID:             id,
		JobType:        domain.JobType(jobType),
		Status:         status,
		IdempotencyKey: payload.IdempotencyKey,
		ScanID:         payload.ScanID,
		StageDetail:    payload.StageDetail,
	}, nil
}

func mapPipelineToJobStatus(status domain.IngestionStatus) string {
	switch status {
	case domain.IngestionStatusNotified, domain.IngestionStatusCompleted:
		return "completed"
	case domain.IngestionStatusFailed:
		return "failed"
	case domain.IngestionStatusRejected:
		return "cancelled"
	default:
		return "running"
	}
}

func mapJobToPipelineStatus(status string) domain.IngestionStatus {
	switch status {
	case "completed":
		return domain.IngestionStatusCompleted
	case "failed":
		return domain.IngestionStatusFailed
	case "cancelled":
		return domain.IngestionStatusRejected
	default:
		return domain.IngestionStatusReceived
	}
}

func errorMessageForStatus(status domain.IngestionStatus, detail string) *string {
	if status == domain.IngestionStatusRejected || status == domain.IngestionStatusFailed {
		return &detail
	}
	return nil
}
