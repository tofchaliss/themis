package ingestion_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

type queueStub struct {
	jobs       []domain.Job
	enqueueErr error
}

func (q *queueStub) Enqueue(_ context.Context, job domain.Job) (string, error) {
	if q.enqueueErr != nil {
		return "", q.enqueueErr
	}
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

func TestSignalsJobHandlerErrors(t *testing.T) {
	handler := ingestion.SignalsJobHandler(nil, nil)
	if err := handler(context.Background(), domain.Job{Payload: []byte("{")}); err == nil {
		t.Fatal("expected decode error")
	}
	if err := handler(context.Background(), domain.Job{Payload: []byte(`{"offset":0,"limit":1}`)}); err == nil {
		t.Fatal("expected nil enrichment error")
	}
}

func TestEnqueueReEnrichSignalsBatchesNilQueue(t *testing.T) {
	dispatcher := &ingestion.AsyncDispatcher{}
	if err := dispatcher.EnqueueReEnrichSignalsBatches(context.Background(), 100); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueReEnrichSignalsBatchesZeroTotal(t *testing.T) {
	queue := &queueStub{}
	dispatcher := &ingestion.AsyncDispatcher{Queue: queue}
	if err := dispatcher.EnqueueReEnrichSignalsBatches(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(queue.jobs) != 0 {
		t.Fatalf("jobs = %d", len(queue.jobs))
	}
}

func TestEnqueueReEnrichSignalsBatchesMarshalError(t *testing.T) {
	original := ingestion.JSONMarshalHook
	ingestion.JSONMarshalHook = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	t.Cleanup(func() { ingestion.JSONMarshalHook = original })

	dispatcher := &ingestion.AsyncDispatcher{Queue: &queueStub{}}
	if err := dispatcher.EnqueueReEnrichSignalsBatches(context.Background(), 100); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueReEnrichSignalsBatchesEnqueueError(t *testing.T) {
	dispatcher := &ingestion.AsyncDispatcher{Queue: &queueStub{enqueueErr: errors.New("queue full")}}
	if err := dispatcher.EnqueueReEnrichSignalsBatches(context.Background(), 100); err == nil {
		t.Fatal("expected error")
	}
}
