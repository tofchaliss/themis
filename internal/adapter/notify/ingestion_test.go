package notify

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestIngestionNotifierNilSender(t *testing.T) {
	notifier := IngestionNotifier{}
	if err := notifier.NotifyComplete(context.Background(), domain.IngestionResult{Status: domain.IngestionStatusNotified}); err != nil {
		t.Fatal(err)
	}
}

func TestIngestionNotifierRejectedEvent(t *testing.T) {
	var dispatched domain.NotificationEvent
	sender := &captureSender{fn: func(_ context.Context, event domain.NotificationEvent) error {
		dispatched = event
		return nil
	}}
	notifier := IngestionNotifier{Sender: sender}
	err := notifier.NotifyComplete(context.Background(), domain.IngestionResult{
		Status: domain.IngestionStatusRejected, Message: "trust gate failed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dispatched.Type != domain.NotificationEventIngestionRejected {
		t.Fatalf("type=%s", dispatched.Type)
	}
}

type captureSender struct {
	fn func(context.Context, domain.NotificationEvent) error
}

func (c *captureSender) Dispatch(ctx context.Context, event domain.NotificationEvent) error {
	return c.fn(ctx, event)
}

func (c *captureSender) FlushDigest(context.Context, string) error { return nil }
