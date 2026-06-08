package ingestion

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

type jobPayload struct {
	Input domain.IngestionInput `json:"input"`
}

var jsonMarshal = json.Marshal

// JSONMarshalHook allows tests to override job payload encoding.
var JSONMarshalHook = jsonMarshal

// AsyncDispatcher enqueues ingestion jobs for worker processing.
type AsyncDispatcher struct {
	Queue domain.JobQueue
}

// EnqueueIngestion schedules async ingestion and returns the job ID.
func (d *AsyncDispatcher) EnqueueIngestion(ctx context.Context, input domain.IngestionInput, jobType domain.JobType) (string, error) {
	if d == nil || d.Queue == nil {
		return "", fmt.Errorf("job queue unavailable")
	}
	payload, err := JSONMarshalHook(jobPayload{Input: input})
	if err != nil {
		return "", err
	}
	job := domain.Job{Type: jobType, Payload: payload}
	if input.IngestionID != "" {
		job.ID = input.IngestionID
	}
	id, err := d.Queue.Enqueue(ctx, job)
	if err != nil {
		return "", err
	}
	return id, nil
}

// EnqueueReenrichVEX schedules asynchronous VEX re-enrichment.
func (d *AsyncDispatcher) EnqueueReenrichVEX(ctx context.Context, vexDocumentID string) error {
	if d == nil || d.Queue == nil {
		return fmt.Errorf("job queue unavailable")
	}
	payload, err := JSONMarshalHook(map[string]string{"vex_document_id": vexDocumentID})
	if err != nil {
		return err
	}
	_, err = d.Queue.Enqueue(ctx, domain.Job{Type: domain.JobTypeReenrichVEX, Payload: payload})
	return err
}
func DecodeJobPayload(job domain.Job) (domain.IngestionInput, domain.JobType, error) {
	var payload jobPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return domain.IngestionInput{}, "", fmt.Errorf("decode job payload: %w", err)
	}
	return payload.Input, job.Type, nil
}

// JobHandler processes queued ingestion and enrichment jobs.
func JobHandler(service Service, enrichmentSvc enrichment.Service) func(context.Context, domain.Job) error {
	ingestHandler := func(ctx context.Context, job domain.Job) error {
		input, jobType, err := DecodeJobPayload(job)
		if err != nil {
			return err
		}
		input.IngestionID = job.ID
		switch jobType {
		case domain.JobTypeIngestVEX:
			_, err = service.IngestVEX(ctx, input)
		default:
			_, err = service.IngestSBOM(ctx, input)
		}
		return err
	}
	return func(ctx context.Context, job domain.Job) error {
		if job.Type == domain.JobTypeReenrichVEX {
			var payload struct {
				VEXDocumentID string `json:"vex_document_id"`
			}
			if err := json.Unmarshal(job.Payload, &payload); err != nil {
				return fmt.Errorf("decode reenrich payload: %w", err)
			}
			if enrichmentSvc == nil {
				return fmt.Errorf("enrichment service unavailable")
			}
			return enrichmentSvc.ReenrichVEX(ctx, payload.VEXDocumentID)
		}
		return ingestHandler(ctx, job)
	}
}
