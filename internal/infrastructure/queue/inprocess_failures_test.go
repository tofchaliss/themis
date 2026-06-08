package queue_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

type markRunningFailStore struct {
	*queue.MemoryJobStore
}

func (s *markRunningFailStore) MarkRunning(context.Context, string) error {
	return errors.New("mark running failed")
}

func TestInProcessQueueMarkRunningFailure(t *testing.T) {
	base := queue.NewMemoryJobStore()
	store := &markRunningFailStore{MemoryJobStore: base}
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize: 1,
		MaxRetry: 1,
		Store:    store,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = q.Stop(context.Background())
	})

	if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}

	waitForStatusCount(t, base, "pending", 1)
}
