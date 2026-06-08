package domain

import "context"

// DatabasePool is the port for checking database connectivity.
type DatabasePool interface {
	Ping(ctx context.Context) error
	Close()
}

// WorkerPool runs background jobs. Implemented in infrastructure/queue.
type WorkerPool interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// JobType identifies asynchronous work dispatched through the job queue.
type JobType string

const (
	JobTypeIngestSBOM     JobType = "ingest_sbom"
	JobTypeIngestVEX      JobType = "ingest_vex"
	JobTypeCorrelateVulns JobType = "correlate_vulns"
	JobTypeReenrichVEX    JobType = "reenrich_vex"
	JobTypeNotify         JobType = "notify"
)

// Job is a unit of asynchronous work.
type Job struct {
	ID      string
	Type    JobType
	Payload []byte
}

// JobQueue dispatches background work. Port implemented in infrastructure/queue.
type JobQueue interface {
	Enqueue(ctx context.Context, job Job) (jobID string, err error)
	Consume(ctx context.Context) (<-chan Job, error)
	Ack(ctx context.Context, jobID string) error
}
