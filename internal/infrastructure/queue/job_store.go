package queue

import "context"

// JobStore persists ingestion job state.
type JobStore interface {
	Create(ctx context.Context, jobID, jobType string, payload []byte) (string, error)
	MarkRunning(ctx context.Context, jobID string) error
	MarkCompleted(ctx context.Context, jobID string) error
	MarkFailed(ctx context.Context, jobID, message string) error
	IncrementAttempts(ctx context.Context, jobID string) (int, error)
	CountByStatus(ctx context.Context, status string) (int, error)
	GetAttempts(ctx context.Context, jobID string) (int, error)
}
