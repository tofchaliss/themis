package notify

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

type stubQueue struct {
	jobs []domain.Job
	err  error
}

func (q *stubQueue) Enqueue(_ context.Context, job domain.Job) (string, error) {
	if q.err != nil {
		return "", q.err
	}
	q.jobs = append(q.jobs, job)
	if job.ID == "" {
		job.ID = "stub-job-id"
	}
	return job.ID, nil
}

func (q *stubQueue) Consume(context.Context) (<-chan domain.Job, error) { return nil, nil }
func (q *stubQueue) Ack(context.Context, string) error                    { return nil }

func TestEnqueueSenderDispatch(t *testing.T) {
	queue := &stubQueue{}
	sender := EnqueueSender{Queue: queue}
	event := domain.NotificationEvent{Type: domain.NotificationEventCVEWatchFinding}
	if err := sender.Dispatch(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(queue.jobs) != 1 || queue.jobs[0].Type != domain.JobTypeNotify {
		t.Fatalf("jobs=%+v", queue.jobs)
	}
	var payload notificationJobPayload
	if err := json.Unmarshal(queue.jobs[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Event.Type != event.Type {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestEnqueueSenderNilQueue(t *testing.T) {
	sender := EnqueueSender{}
	if err := sender.Dispatch(context.Background(), domain.NotificationEvent{}); err != nil {
		t.Fatal(err)
	}
	if err := sender.FlushDigest(context.Background(), "batch"); err != nil {
		t.Fatal(err)
	}
}

func TestEnqueueSenderFlushDigest(t *testing.T) {
	queue := &stubQueue{}
	sender := EnqueueSender{Queue: queue}
	if err := sender.FlushDigest(context.Background(), "cycle-1"); err != nil {
		t.Fatal(err)
	}
	var payload notificationJobPayload
	if err := json.Unmarshal(queue.jobs[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.FlushKey != "cycle-1" {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestEnqueueSenderQueueError(t *testing.T) {
	sender := EnqueueSender{Queue: &stubQueue{err: errors.New("queue down")}}
	if err := sender.Dispatch(context.Background(), domain.NotificationEvent{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnqueueSenderNotifyTeam(t *testing.T) {
	queue := &stubQueue{}
	sender := EnqueueSender{Queue: queue}
	event := domain.NotificationEvent{Type: domain.NotificationEventTriageDecision, Message: "team blast"}
	if err := sender.NotifyTeam(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(queue.jobs) != 1 {
		t.Fatalf("jobs=%+v", queue.jobs)
	}
}

func TestEnqueueSenderMarshalError(t *testing.T) {
	orig := marshalJobPayload
	marshalJobPayload = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	t.Cleanup(func() { marshalJobPayload = orig })

	sender := EnqueueSender{Queue: &stubQueue{}}
	if err := sender.Dispatch(context.Background(), domain.NotificationEvent{}); err == nil {
		t.Fatal("expected marshal error")
	}
	if err := sender.FlushDigest(context.Background(), "batch"); err == nil {
		t.Fatal("expected marshal error")
	}
}
