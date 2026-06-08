package queue_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

func TestBackoffDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 0, want: time.Second},
		{attempt: 1, want: time.Second},
		{attempt: 2, want: 2 * time.Second},
		{attempt: 3, want: 4 * time.Second},
		{attempt: 20, want: time.Hour},
	}

	for _, tt := range tests {
		got := queue.BackoffDelay(time.Second, tt.attempt)
		if got != tt.want {
			t.Fatalf("BackoffDelay(1s, %d) = %s, want %s", tt.attempt, got, tt.want)
		}
	}
	if queue.BackoffDelay(0, 2) != 0 {
		t.Fatal("expected zero delay for zero base")
	}
}

func TestNewInProcessQueueRequiresStore(t *testing.T) {
	_, err := queue.NewInProcessQueue(queue.InProcessConfig{})
	if err == nil {
		t.Fatal("expected error without store")
	}
}

func TestInProcessQueueEnqueueConsumeOrdering(t *testing.T) {
	store := queue.NewMemoryJobStore()
	var order []string
	var mu sync.Mutex

	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
		Store:     store,
		Handler: func(_ context.Context, job domain.Job) error {
			mu.Lock()
			order = append(order, job.ID)
			mu.Unlock()
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
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = q.Stop(stopCtx)
	})

	jobs, err := q.Consume(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if jobs == nil {
		t.Fatal("expected jobs channel")
	}

	for i := 0; i < 5; i++ {
		if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM, Payload: []byte(`{"n":` + string(rune('0'+i)) + `}`)}); err != nil {
			t.Fatalf("Enqueue() error = %v", err)
		}
	}

	waitForStatusCount(t, store, "completed", 5)

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 5 {
		t.Fatalf("processed order len = %d, want 5", len(order))
	}
}

func TestInProcessQueueConcurrency(t *testing.T) {
	store := queue.NewMemoryJobStore()
	var active int32
	var peak int32

	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  4,
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
		Store:     store,
		Handler: func(_ context.Context, _ domain.Job) error {
			current := atomic.AddInt32(&active, 1)
			for {
				oldPeak := atomic.LoadInt32(&peak)
				if current <= oldPeak || atomic.CompareAndSwapInt32(&peak, oldPeak, current) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&active, -1)
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
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = q.Stop(stopCtx)
	})

	for i := 0; i < 20; i++ {
		if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
			t.Fatal(err)
		}
	}

	waitForStatusCount(t, store, "completed", 20)
	if peak > 4 {
		t.Fatalf("peak concurrency = %d, want <= 4", peak)
	}
}

func TestInProcessQueueAckMarksCompleted(t *testing.T) {
	store := queue.NewMemoryJobStore()
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
		Store:     store,
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

	if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}
	waitForStatusCount(t, store, "completed", 1)
}

func TestInProcessQueueRetryAndMaxFailure(t *testing.T) {
	store := queue.NewMemoryJobStore()
	var sleeps []time.Duration
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  3,
		BaseDelay: 10 * time.Millisecond,
		Store:     store,
		Handler: func(_ context.Context, _ domain.Job) error {
			return errors.New("boom")
		},
		Sleep: func(_ context.Context, delay time.Duration) error {
			sleeps = append(sleeps, delay)
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
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = q.Stop(stopCtx)
	})

	if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}

	waitForStatusCount(t, store, "failed", 1)
	if len(sleeps) != 2 {
		t.Fatalf("sleep calls = %d, want 2", len(sleeps))
	}
	if sleeps[0] != 10*time.Millisecond || sleeps[1] != 20*time.Millisecond {
		t.Fatalf("unexpected backoff sleeps: %v", sleeps)
	}
}

func TestInProcessQueueGracefulShutdownDrainsInFlight(t *testing.T) {
	store := queue.NewMemoryJobStore()
	started := make(chan struct{}, 2)
	release := make(chan struct{})

	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  2,
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
		Store:     store,
		Handler: func(_ context.Context, _ domain.Job) error {
			started <- struct{}{}
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

	if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}

	<-started
	<-started

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { close(release) }()

	if err := q.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	waitForStatusCount(t, store, "completed", 2)
}

func TestInProcessQueueLifecycleErrors(t *testing.T) {
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
	if _, err := q.Consume(ctx); !errors.Is(err, queue.ErrQueueNotStarted) {
		t.Fatalf("Consume() error = %v", err)
	}

	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := q.Start(ctx); !errors.Is(err, queue.ErrQueueAlreadyStarted) {
		t.Fatalf("Start() twice error = %v", err)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := q.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}

	if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); !errors.Is(err, queue.ErrQueueStopped) {
		t.Fatalf("Enqueue() after stop error = %v", err)
	}
}

func TestMemoryJobStoreErrors(t *testing.T) {
	store := queue.NewMemoryJobStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.Create(ctx, "", "ingest_sbom", nil); err == nil {
		t.Fatal("expected cancelled context error")
	}
	if err := store.MarkRunning(ctx, "missing"); err == nil {
		t.Fatal("expected error for missing job")
	}
}

func waitForStatusCount(t *testing.T, store *queue.MemoryJobStore, status string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		count, err := store.CountByStatus(context.Background(), status)
		if err != nil {
			t.Fatalf("CountByStatus() error = %v", err)
		}
		if count == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	count, _ := store.CountByStatus(context.Background(), status)
	t.Fatalf("status %q count = %d, want %d", status, count, want)
}
