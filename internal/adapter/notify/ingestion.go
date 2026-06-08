package notify

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// IngestionNotifier dispatches ingestion completion notifications.
type IngestionNotifier struct {
	Sender domain.NotificationSender
}

// NotifyComplete dispatches an ingestion completion notification.
func (n IngestionNotifier) NotifyComplete(ctx context.Context, result domain.IngestionResult) error {
	if n.Sender == nil {
		return nil
	}
	eventType := domain.NotificationEventIngestionCompleted
	if result.Status == domain.IngestionStatusRejected || result.Status == domain.IngestionStatusFailed {
		eventType = domain.NotificationEventIngestionRejected
	}
	return n.Sender.Dispatch(ctx, domain.NotificationEvent{
		Type:        eventType,
		ScanID:      result.ScanID,
		IngestionID: result.IngestionID,
		Message:     result.Message,
	})
}
