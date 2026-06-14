package ingestion_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

type queueStub struct {
	jobs []domain.Job
}

func (q *queueStub) Enqueue(_ context.Context, job domain.Job) (string, error) {
	q.jobs = append(q.jobs, job)
	return "job-id", nil
}
func (q *queueStub) Consume(context.Context) (<-chan domain.Job, error) { return nil, nil }
func (q *queueStub) Ack(context.Context, string) error                   { return nil }

func TestEnqueueReEnrichSignalsBatches(t *testing.T) {
	queue := &queueStub{}
	dispatcher := &ingestion.AsyncDispatcher{Queue: queue}
	if err := dispatcher.EnqueueReEnrichSignalsBatches(context.Background(), 1200); err != nil {
		t.Fatalf("EnqueueReEnrichSignalsBatches() error = %v", err)
	}
	if len(queue.jobs) != 3 {
		t.Fatalf("jobs = %d, want 3", len(queue.jobs))
	}
	for _, job := range queue.jobs {
		if job.Type != domain.JobTypeReEnrichSignals {
			t.Fatalf("job type = %q", job.Type)
		}
	}
}

func TestSignalsJobHandler(t *testing.T) {
	handler := ingestion.SignalsJobHandler(&enrichment.Handler{}, nil)
	err := handler(context.Background(), domain.Job{
		Type:    domain.JobTypeReEnrichSignals,
		Payload: []byte(`{"offset":0,"limit":500}`),
	})
	if err != nil {
		t.Fatalf("SignalsJobHandler() error = %v", err)
	}
}
