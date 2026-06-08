package notify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/domain"
)

type notificationJobPayload struct {
	Event    domain.NotificationEvent `json:"event,omitempty"`
	FlushKey string                   `json:"flush_key,omitempty"`
}

// JobHandler processes queued notification delivery jobs.
func JobHandler(svc *Service) func(context.Context, domain.Job) error {
	return func(ctx context.Context, job domain.Job) error {
		if svc == nil {
			return nil
		}
		var payload notificationJobPayload
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			return fmt.Errorf("decode notification job: %w", err)
		}
		if payload.FlushKey != "" {
			return svc.FlushDigest(ctx, payload.FlushKey)
		}
		return svc.Dispatch(ctx, payload.Event)
	}
}
