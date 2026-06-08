package queue

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/metrics"
)

// JobHandler processes a dequeued job.
type JobHandler func(ctx context.Context, job domain.Job) error

// InProcessConfig configures the in-process worker pool.
type InProcessConfig struct {
	PoolSize   int
	MaxRetry   int
	BaseDelay  time.Duration
	BufferSize int
	Handler    JobHandler
	Store      JobStore
	Sleep      func(context.Context, time.Duration) error
}

// InProcessQueue implements domain.JobQueue and domain.WorkerPool.
type InProcessQueue struct {
	cfg InProcessConfig

	jobs chan domain.Job

	mu       sync.RWMutex
	started  bool
	stopping bool

	wg sync.WaitGroup
}

// ErrQueueStopped is returned when enqueue is attempted after shutdown begins.
var ErrQueueStopped = errors.New("job queue is stopped")

// ErrQueueNotStarted is returned when consume is called before start.
var ErrQueueNotStarted = errors.New("job queue is not started")

// ErrQueueAlreadyStarted is returned when start is called twice.
var ErrQueueAlreadyStarted = errors.New("job queue is already started")

// NewInProcessQueue creates an in-process queue backed by store.
func NewInProcessQueue(cfg InProcessConfig) (*InProcessQueue, error) {
	if cfg.Store == nil {
		return nil, errors.New("job store is required")
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 1
	}
	if cfg.MaxRetry <= 0 {
		cfg.MaxRetry = 1
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = cfg.PoolSize * 2
	}
	if cfg.Handler == nil {
		cfg.Handler = func(context.Context, domain.Job) error { return nil }
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepContext
	}

	return &InProcessQueue{
		cfg:  cfg,
		jobs: make(chan domain.Job, cfg.BufferSize),
	}, nil
}

// SetHandler replaces the job handler at runtime (used during HTTP wiring).
func (q *InProcessQueue) SetHandler(handler JobHandler) {
	q.cfg.Handler = handler
}

// Enqueue persists and schedules a job for processing.
func (q *InProcessQueue) Enqueue(ctx context.Context, job domain.Job) (string, error) {
	q.mu.RLock()
	stopping := q.stopping
	q.mu.RUnlock()
	if stopping {
		return "", ErrQueueStopped
	}

	id, err := q.cfg.Store.Create(ctx, job.ID, string(job.Type), job.Payload)
	if err != nil {
		return "", err
	}
	job.ID = id

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case q.jobs <- job:
		q.refreshQueueDepth()
		return job.ID, nil
	}
}

// Consume returns the channel workers read jobs from.
func (q *InProcessQueue) Consume(_ context.Context) (<-chan domain.Job, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if !q.started {
		return nil, ErrQueueNotStarted
	}
	return q.jobs, nil
}

// Ack marks a job as completed.
func (q *InProcessQueue) Ack(ctx context.Context, jobID string) error {
	return q.cfg.Store.MarkCompleted(ctx, jobID)
}

// Start launches worker goroutines.
func (q *InProcessQueue) Start(ctx context.Context) error {
	q.mu.Lock()
	if q.started {
		q.mu.Unlock()
		return ErrQueueAlreadyStarted
	}
	q.started = true
	q.mu.Unlock()

	for i := 0; i < q.cfg.PoolSize; i++ {
		q.wg.Add(1)
		go q.worker(ctx, q.jobs)
	}
	return nil
}

// Stop drains in-flight jobs before returning.
func (q *InProcessQueue) Stop(ctx context.Context) error {
	q.mu.Lock()
	if !q.started {
		q.mu.Unlock()
		return nil
	}
	if q.stopping {
		q.mu.Unlock()
		return q.wait(ctx)
	}
	q.stopping = true
	close(q.jobs)
	q.mu.Unlock()

	return q.wait(ctx)
}

func (q *InProcessQueue) wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *InProcessQueue) worker(ctx context.Context, jobs <-chan domain.Job) {
	defer q.wg.Done()
	for job := range jobs {
		q.process(ctx, job)
	}
}

func (q *InProcessQueue) process(ctx context.Context, job domain.Job) {
	q.refreshQueueDepth()
	if err := q.cfg.Store.MarkRunning(ctx, job.ID); err != nil {
		return
	}

	if err := q.cfg.Handler(ctx, job); err != nil {
		q.handleFailure(ctx, job, err)
		return
	}

	_ = q.Ack(ctx, job.ID)
}

func (q *InProcessQueue) handleFailure(ctx context.Context, job domain.Job, handlerErr error) {
	persistCtx := context.WithoutCancel(ctx)

	attempts, err := q.cfg.Store.IncrementAttempts(persistCtx, job.ID)
	if err != nil {
		return
	}

	if attempts >= q.cfg.MaxRetry {
		_ = q.cfg.Store.MarkFailed(persistCtx, job.ID, handlerErr.Error())
		return
	}

	delay := BackoffDelay(q.cfg.BaseDelay, attempts)
	if delay > 0 {
		if err := q.cfg.Sleep(ctx, delay); err != nil {
			_ = q.cfg.Store.MarkFailed(persistCtx, job.ID, err.Error())
			return
		}
	}

	q.mu.RLock()
	stopping := q.stopping
	q.mu.RUnlock()
	if stopping {
		_ = q.cfg.Store.MarkFailed(persistCtx, job.ID, "queue stopped during retry")
		return
	}

	select {
	case <-ctx.Done():
		_ = q.cfg.Store.MarkFailed(persistCtx, job.ID, ctx.Err().Error())
	case q.jobs <- job:
	}
}

func (q *InProcessQueue) refreshQueueDepth() {
	metrics.SetQueueDepth(len(q.jobs))
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
