package ingestion

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

const defaultReEnrichBatchSize = 500

type reEnrichSignalsPayload struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// EnqueueReEnrichSignalsBatches schedules batched signal re-enrichment jobs.
func (d *AsyncDispatcher) EnqueueReEnrichSignalsBatches(ctx context.Context, totalOpen int) error {
	if d == nil || d.Queue == nil {
		return fmt.Errorf("job queue unavailable")
	}
	batchSize := defaultReEnrichBatchSize
	for offset := 0; offset < totalOpen; offset += batchSize {
		payload, err := JSONMarshalHook(reEnrichSignalsPayload{Offset: offset, Limit: batchSize})
		if err != nil {
			return err
		}
		if _, err := d.Queue.Enqueue(ctx, domain.Job{
			Type:    domain.JobTypeReEnrichSignals,
			Payload: payload,
		}); err != nil {
			return err
		}
	}
	return nil
}

// SignalsJobHandler processes reenrich_signals jobs.
func SignalsJobHandler(svc *enrichment.Handler, signals enrichment.SignalReader) func(context.Context, domain.Job) error {
	return func(ctx context.Context, job domain.Job) error {
		var payload reEnrichSignalsPayload
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			return fmt.Errorf("decode reenrich signals payload: %w", err)
		}
		if svc == nil {
			return fmt.Errorf("enrichment service unavailable")
		}
		return svc.ReEnrichSignalsBatch(ctx, payload.Offset, payload.Limit, signals)
	}
}
