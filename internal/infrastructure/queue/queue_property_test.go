package queue_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

// TestInProcessQueueProperty enqueues a random mix of always-succeeding and
// always-failing jobs and asserts the queue invariants:
//   - every job reaches a terminal state (no job lost, none left pending/running);
//   - good jobs complete, bad jobs fail;
//   - completed + failed == total;
//   - failing jobs are retried a bounded number of times (attempts == MaxRetry).
func TestInProcessQueueProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 8).Draw(t, "jobs")
		poolSize := rapid.IntRange(1, 4).Draw(t, "pool")
		maxRetry := rapid.IntRange(1, 4).Draw(t, "max_retry")

		good := make([]bool, n)
		for i := range good {
			good[i] = rapid.Bool().Draw(t, "good")
		}

		store := queue.NewMemoryJobStore()
		ids := make([]string, n)
		goodByID := make(map[string]bool, n)
		ctx := context.Background()
		for i := 0; i < n; i++ {
			id, err := store.Create(ctx, "", "test", []byte{byte(i)})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			ids[i] = id
			goodByID[id] = good[i]
		}

		q, err := queue.NewInProcessQueue(queue.InProcessConfig{
			PoolSize:   poolSize,
			MaxRetry:   maxRetry,
			BaseDelay:  0,
			BufferSize: n * (maxRetry + 2),
			Store:      store,
			Sleep:      func(context.Context, time.Duration) error { return nil },
			Handler: func(_ context.Context, job domain.Job) error {
				if goodByID[job.ID] {
					return nil
				}
				return errors.New("intentional failure")
			},
		})
		if err != nil {
			t.Fatalf("new queue: %v", err)
		}
		if err := q.Start(ctx); err != nil {
			t.Fatalf("start: %v", err)
		}
		for _, id := range ids {
			if _, err := q.Enqueue(ctx, domain.Job{ID: id, Type: "test", Payload: []byte("x")}); err != nil {
				t.Fatalf("enqueue: %v", err)
			}
		}

		deadline := time.Now().Add(3 * time.Second)
		for {
			completed, _ := store.CountByStatus(ctx, "completed")
			failed, _ := store.CountByStatus(ctx, "failed")
			if completed+failed == n {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("timeout: completed=%d failed=%d want total=%d", completed, failed, n)
			}
			time.Sleep(time.Millisecond)
		}

		stopCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := q.Stop(stopCtx); err != nil {
			t.Fatalf("stop: %v", err)
		}

		pending, _ := store.CountByStatus(ctx, "pending")
		running, _ := store.CountByStatus(ctx, "running")
		if pending != 0 || running != 0 {
			t.Fatalf("jobs left in flight: pending=%d running=%d", pending, running)
		}
		completed, _ := store.CountByStatus(ctx, "completed")
		failed, _ := store.CountByStatus(ctx, "failed")
		if completed+failed != n {
			t.Fatalf("job lost: completed=%d failed=%d total=%d", completed, failed, n)
		}

		for i, id := range ids {
			attempts, err := store.GetAttempts(ctx, id)
			if err != nil {
				t.Fatalf("attempts: %v", err)
			}
			if good[i] {
				if attempts != 0 {
					t.Fatalf("good job %s had %d attempts, want 0", id, attempts)
				}
				continue
			}
			if attempts != maxRetry {
				t.Fatalf("failing job %s attempts = %d want %d", id, attempts, maxRetry)
			}
		}
	})
}
