package metrics

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

// InstrumentedNotifier records notification delivery metrics around a delegate.
type InstrumentedNotifier struct {
	Inner      domain.IngestionNotifier
	ChannelTyp string
}

// NotifyComplete dispatches and records delivery outcome.
func (n InstrumentedNotifier) NotifyComplete(ctx context.Context, result domain.IngestionResult) error {
	channel := n.ChannelTyp
	if channel == "" {
		channel = "ingestion"
	}
	err := n.Inner.NotifyComplete(ctx, result)
	if err != nil {
		RecordNotification(channel, "failure")
		return err
	}
	RecordNotification(channel, "success")
	return nil
}

// InstrumentJobHandler wraps a queue handler with ingestion job metrics.
func InstrumentJobHandler(handler func(context.Context, domain.Job) error) func(context.Context, domain.Job) error {
	return func(ctx context.Context, job domain.Job) error {
		ActiveWorkers.Inc()
		defer ActiveWorkers.Dec()

		start := time.Now()
		err := handler(ctx, job)
		status := "success"
		if err != nil {
			status = "failure"
		}
		RecordIngestionJob(string(job.Type), status, time.Since(start))
		return err
	}
}
