package ingestion_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

type stubEnrichment struct {
	reenrich func(context.Context, string) error
}

func (s stubEnrichment) ApplyVEX(context.Context, string) error { return nil }

func (s stubEnrichment) ReenrichVEX(ctx context.Context, vexDocumentID string) error {
	if s.reenrich != nil {
		return s.reenrich(ctx, vexDocumentID)
	}
	return nil
}

func TestJobHandlerReenrichVEX(t *testing.T) {
	called := false
	handler := ingestion.JobHandler(nil, stubEnrichment{reenrich: func(_ context.Context, vexID string) error {
		called = true
		if vexID != "vex-1" {
			t.Fatalf("vexID = %q", vexID)
		}
		return nil
	}})
	payload, _ := json.Marshal(map[string]string{"vex_document_id": "vex-1"})
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeReenrichVEX, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected reenrich call")
	}
}

func TestEnqueueReenrichVEX(t *testing.T) {
	queue := &memoryQueue{}
	dispatcher := &ingestion.AsyncDispatcher{Queue: queue}
	if err := dispatcher.EnqueueReenrichVEX(context.Background(), "vex-1"); err != nil {
		t.Fatal(err)
	}
	if queue.last.Type != domain.JobTypeReenrichVEX {
		t.Fatalf("job type = %q", queue.last.Type)
	}
}

func TestEnqueueReenrichVEXNilQueue(t *testing.T) {
	dispatcher := &ingestion.AsyncDispatcher{}
	if err := dispatcher.EnqueueReenrichVEX(context.Background(), "vex-1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueIngestion(t *testing.T) {
	queue := &memoryQueue{}
	dispatcher := &ingestion.AsyncDispatcher{Queue: queue}
	input := domain.IngestionInput{IngestionID: "ing-1"}
	id, err := dispatcher.EnqueueIngestion(context.Background(), input, domain.JobTypeIngestSBOM)
	if err != nil {
		t.Fatal(err)
	}
	if id != "ing-1" || queue.last.Type != domain.JobTypeIngestSBOM {
		t.Fatalf("job = %+v id=%q", queue.last, id)
	}
}

func TestEnqueueIngestionReturnsGeneratedID(t *testing.T) {
	queue := &memoryQueue{}
	dispatcher := &ingestion.AsyncDispatcher{Queue: queue}
	id, err := dispatcher.EnqueueIngestion(context.Background(), domain.IngestionInput{}, domain.JobTypeIngestSBOM)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || id == "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("id = %q, want generated job id", id)
	}
}

func TestEnqueueIngestionNilQueue(t *testing.T) {
	dispatcher := &ingestion.AsyncDispatcher{}
	_, err := dispatcher.EnqueueIngestion(context.Background(), domain.IngestionInput{}, domain.JobTypeIngestSBOM)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeJobPayload(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"input": map[string]any{"format": "cyclonedx"}})
	input, jobType, err := ingestion.DecodeJobPayload(domain.Job{Type: domain.JobTypeIngestSBOM, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if jobType != domain.JobTypeIngestSBOM || input.Format != "cyclonedx" {
		t.Fatalf("input=%+v type=%q", input, jobType)
	}
}

func TestDecodeJobPayloadError(t *testing.T) {
	_, _, err := ingestion.DecodeJobPayload(domain.Job{Payload: []byte("{")})
	if err == nil {
		t.Fatal("expected error")
	}
}

type stubIngestionService struct {
	lastType domain.JobType
	called   bool
}

func (s *stubIngestionService) IngestSBOM(context.Context, domain.IngestionInput) (domain.IngestionResult, error) {
	s.called = true
	s.lastType = domain.JobTypeIngestSBOM
	return domain.IngestionResult{}, nil
}

func (s *stubIngestionService) IngestVEX(context.Context, domain.IngestionInput) (domain.IngestionResult, error) {
	s.called = true
	s.lastType = domain.JobTypeIngestVEX
	return domain.IngestionResult{}, nil
}

func TestJobHandlerIngestSBOM(t *testing.T) {
	svc := &stubIngestionService{}
	handler := ingestion.JobHandler(svc, stubEnrichment{})
	payload, _ := json.Marshal(map[string]any{"input": map[string]any{"format": "cyclonedx"}})
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeIngestSBOM, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if !svc.called || svc.lastType != domain.JobTypeIngestSBOM {
		t.Fatal("expected sbom ingest")
	}
}

func TestJobHandlerIngestVEX(t *testing.T) {
	svc := &stubIngestionService{}
	handler := ingestion.JobHandler(svc, stubEnrichment{})
	payload, _ := json.Marshal(map[string]any{"input": map[string]any{"format": "openvex"}})
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeIngestVEX, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if !svc.called || svc.lastType != domain.JobTypeIngestVEX {
		t.Fatal("expected vex ingest")
	}
}

func TestJobHandlerReenrichBadPayload(t *testing.T) {
	handler := ingestion.JobHandler(nil, stubEnrichment{})
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeReenrichVEX, Payload: []byte("{")}); err == nil {
		t.Fatal("expected error")
	}
}

func TestJobHandlerReenrichNilEnrichment(t *testing.T) {
	handler := ingestion.JobHandler(nil, nil)
	payload, _ := json.Marshal(map[string]string{"vex_document_id": "vex-1"})
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeReenrichVEX, Payload: payload}); err == nil {
		t.Fatal("expected error")
	}
}

func TestJobHandlerDecodeError(t *testing.T) {
	handler := ingestion.JobHandler(&stubIngestionService{}, stubEnrichment{})
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeIngestSBOM, Payload: []byte("not-json")}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueIngestionMarshalError(t *testing.T) {
	original := ingestion.JSONMarshalHook
	ingestion.JSONMarshalHook = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	t.Cleanup(func() { ingestion.JSONMarshalHook = original })

	dispatcher := &ingestion.AsyncDispatcher{Queue: &memoryQueue{}}
	_, err := dispatcher.EnqueueIngestion(context.Background(), domain.IngestionInput{}, domain.JobTypeIngestSBOM)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueReenrichVEXMarshalError(t *testing.T) {
	original := ingestion.JSONMarshalHook
	ingestion.JSONMarshalHook = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	t.Cleanup(func() { ingestion.JSONMarshalHook = original })

	dispatcher := &ingestion.AsyncDispatcher{Queue: &memoryQueue{}}
	if err := dispatcher.EnqueueReenrichVEX(context.Background(), "vex-1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueIngestionEnqueueError(t *testing.T) {
	dispatcher := &ingestion.AsyncDispatcher{Queue: &memoryQueue{enqueueErr: errors.New("queue full")}}
	_, err := dispatcher.EnqueueIngestion(context.Background(), domain.IngestionInput{}, domain.JobTypeIngestSBOM)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueReenrichVEXEnqueueError(t *testing.T) {
	dispatcher := &ingestion.AsyncDispatcher{Queue: &memoryQueue{enqueueErr: errors.New("queue full")}}
	if err := dispatcher.EnqueueReenrichVEX(context.Background(), "vex-1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueApplyVEXForSBOMs(t *testing.T) {
	queue := &memoryQueue{}
	dispatcher := &ingestion.AsyncDispatcher{Queue: queue}
	if err := dispatcher.EnqueueApplyVEXForSBOMs(context.Background(), []string{"", "sbom-1", "sbom-2"}); err != nil {
		t.Fatal(err)
	}
	if queue.count != 2 {
		t.Fatalf("jobs = %d, want 2", queue.count)
	}
}

func TestEnqueueApplyVEXForSBOMsNilQueue(t *testing.T) {
	dispatcher := &ingestion.AsyncDispatcher{}
	if err := dispatcher.EnqueueApplyVEXForSBOMs(context.Background(), []string{"sbom-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueApplyVEXForSBOMsMarshalError(t *testing.T) {
	original := ingestion.JSONMarshalHook
	ingestion.JSONMarshalHook = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	t.Cleanup(func() { ingestion.JSONMarshalHook = original })

	dispatcher := &ingestion.AsyncDispatcher{Queue: &memoryQueue{}}
	if err := dispatcher.EnqueueApplyVEXForSBOMs(context.Background(), []string{"sbom-1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueApplyVEXForSBOMsEnqueueError(t *testing.T) {
	dispatcher := &ingestion.AsyncDispatcher{Queue: &memoryQueue{enqueueErr: errors.New("queue full")}}
	if err := dispatcher.EnqueueApplyVEXForSBOMs(context.Background(), []string{"sbom-1"}); err == nil {
		t.Fatal("expected error")
	}
}

type memoryQueue struct {
	last       domain.Job
	enqueueErr error
	count      int
}

func (m *memoryQueue) Enqueue(_ context.Context, job domain.Job) (string, error) {
	if m.enqueueErr != nil {
		return "", m.enqueueErr
	}
	m.count++
	m.last = job
	if job.ID == "" {
		job.ID = "generated-job-id"
	}
	m.last = job
	return job.ID, nil
}

func (m *memoryQueue) Consume(context.Context) (<-chan domain.Job, error) { return nil, nil }
func (m *memoryQueue) Ack(context.Context, string) error                  { return nil }
