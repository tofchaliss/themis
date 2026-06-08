package queue_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

func TestMemoryJobStoreGetAttempts(t *testing.T) {
	store := queue.NewMemoryJobStore()
	ctx := context.Background()

	id, err := store.Create(ctx, string(domain.JobTypeIngestSBOM), nil)
	if err != nil {
		t.Fatal(err)
	}

	attempts, err := store.GetAttempts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("attempts = %d, want 0", attempts)
	}

	if _, err := store.IncrementAttempts(ctx, id); err != nil {
		t.Fatal(err)
	}
	attempts, err = store.GetAttempts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}

	if _, err := store.GetAttempts(ctx, "missing"); err == nil {
		t.Fatal("expected missing job error")
	}
}

func TestInProcessQueueDefaults(t *testing.T) {
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize: 0,
		MaxRetry: 0,
		Store:    queue.NewMemoryJobStore(),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = q.Stop(stopCtx)
	})

	if err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}
}

func TestInProcessQueueEnqueueContextCancelled(t *testing.T) {
	store := queue.NewMemoryJobStore()
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:   1,
		MaxRetry:   1,
		BufferSize: 1,
		Store:      store,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err == nil {
		t.Fatal("expected cancelled context error")
	}
}

func TestInProcessQueueStopWithoutStart(t *testing.T) {
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize: 1,
		MaxRetry: 1,
		Store:    queue.NewMemoryJobStore(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() without start error = %v", err)
	}
}

func TestInProcessQueueStopTimeout(t *testing.T) {
	store := queue.NewMemoryJobStore()
	release := make(chan struct{})
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
		Store:     store,
		Handler: func(_ context.Context, _ domain.Job) error {
			<-release
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := q.Stop(stopCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop() error = %v, want deadline exceeded", err)
	}
	close(release)
}

func TestInProcessQueueFailureSleepCancelled(t *testing.T) {
	store := queue.NewMemoryJobStore()
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  5,
		BaseDelay: time.Second,
		Store:     store,
		Handler: func(_ context.Context, _ domain.Job) error {
			return errors.New("fail")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		_ = q.Stop(stopCtx)
	})

	if err := q.Enqueue(context.Background(), domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond)
	cancel()
	waitForStatusCount(t, store, "failed", 1)
}

func TestInProcessQueueFailureWhileStopping(t *testing.T) {
	store := queue.NewMemoryJobStore()
	block := make(chan struct{})
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  10,
		BaseDelay: time.Millisecond,
		Store:     store,
		Handler: func(_ context.Context, _ domain.Job) error {
			<-block
			return errors.New("fail")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond)
	close(block)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestInProcessQueueDirectAck(t *testing.T) {
	store := queue.NewMemoryJobStore()
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize: 1,
		MaxRetry: 1,
		Store:    store,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	id, err := store.Create(ctx, string(domain.JobTypeIngestSBOM), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Ack(ctx, id); err != nil {
		t.Fatalf("Ack() error = %v", err)
	}
}
