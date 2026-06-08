package queue

import "context"

// NoopWorkerPool is a placeholder until the in-process queue is wired in task group 4.
type NoopWorkerPool struct{}

// Start implements domain.WorkerPool.
func (NoopWorkerPool) Start(context.Context) error { return nil }

// Stop implements domain.WorkerPool.
func (NoopWorkerPool) Stop(context.Context) error { return nil }
