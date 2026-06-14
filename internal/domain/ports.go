package domain

import (
	"context"
	"time"
)

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
	JobTypeIngestSBOM      JobType = "ingest_sbom"
	JobTypeIngestVEX       JobType = "ingest_vex"
	JobTypeCorrelateVulns  JobType = "correlate_vulns"
	JobTypeReenrichVEX     JobType = "reenrich_vex"
	JobTypeReEnrichSignals JobType = "reenrich_signals"
	JobTypeSyncVEXFeed     JobType = "sync_vex_feed"
	JobTypeApplyVEXSBOM    JobType = "apply_vex_sbom"
	JobTypeNotify          JobType = "notify"
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

// ThreatSignalFetcher retrieves EPSS and KEV intelligence feeds.
type ThreatSignalFetcher interface {
	FetchEPSS(ctx context.Context) ([]EPSSSignal, error)
	FetchKEV(ctx context.Context) ([]KEVSignal, error)
}

// ExploitSource retrieves public exploit records.
type ExploitSource interface {
	FetchExploits(ctx context.Context) ([]ExploitRecord, error)
}

// GraphStore manages asset graph nodes, edges, and blast-radius queries.
type GraphStore interface {
	CreateMicroservice(ctx context.Context, ms Microservice) (Microservice, error)
	CreateDeployment(ctx context.Context, dep Deployment) (Deployment, error)
	CreateCustomer(ctx context.Context, customer Customer) (Customer, error)
	GetMicroservice(ctx context.Context, id string) (Microservice, error)
	GetCustomer(ctx context.Context, id string) (Customer, error)
	ComputeBlastRadius(ctx context.Context, finding EnrichmentFinding) (BlastRadiusResult, error)
	ProductBlastRadius(ctx context.Context, productID, vulnerabilityID, componentID string) (BlastRadiusResult, error)
}

// ThreatSignalStore persists EPSS/KEV signal data keyed by CVE.
type ThreatSignalStore interface {
	UpsertEPSS(ctx context.Context, signals []EPSSSignal) error
	UpsertKEV(ctx context.Context, signals []KEVSignal) error
	ListKEVCVEIDs(ctx context.Context) ([]string, error)
	MarkStale(ctx context.Context, stale bool) error
	SignalsStale(ctx context.Context) (bool, error)
	GetEPSSForCVE(ctx context.Context, cveID string) (*float64, error)
	IsKEVListed(ctx context.Context, cveID string) (bool, error)
	CountEPSSRows(ctx context.Context) (int, error)
	LastSuccessfulFetch(ctx context.Context) (time.Time, error)
}

// ExploitStore persists exploit records and answers CVE lookups.
type ExploitStore interface {
	UpsertExploits(ctx context.Context, records []ExploitRecord) error
	HasPublicExploit(ctx context.Context, cveID string) (bool, error)
	CountExploits(ctx context.Context) (int, error)
}
