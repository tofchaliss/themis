package notify

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/themis-project/themis/internal/domain"
)

var marshalJobPayload = json.Marshal

// EnqueueSender enqueues notification events for asynchronous delivery.
type EnqueueSender struct {
	Queue domain.JobQueue
}

// Dispatch enqueues a notification job.
func (e EnqueueSender) Dispatch(ctx context.Context, event domain.NotificationEvent) error {
	if e.Queue == nil {
		return nil
	}
	payload, err := marshalJobPayload(notificationJobPayload{Event: event})
	if err != nil {
		return err
	}
	return e.Queue.Enqueue(ctx, domain.Job{
		ID:      uuid.NewString(),
		Type:    domain.JobTypeNotify,
		Payload: payload,
	})
}

// FlushDigest enqueues a digest flush job for the given batch key.
func (e EnqueueSender) FlushDigest(ctx context.Context, batchKey string) error {
	if e.Queue == nil || batchKey == "" {
		return nil
	}
	payload, err := marshalJobPayload(notificationJobPayload{FlushKey: batchKey})
	if err != nil {
		return err
	}
	return e.Queue.Enqueue(ctx, domain.Job{
		ID:      uuid.NewString(),
		Type:    domain.JobTypeNotify,
		Payload: payload,
	})
}
