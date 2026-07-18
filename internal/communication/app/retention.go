package app

import (
	"context"
	"time"
)

// RetentionService is the retention/pruning worker (D1/D11): it caps payload storage by
// dropping the heavy rendered bytes of delivered Publications past a retention window, while
// keeping the permanent lineage metadata. Pruned payloads are regenerable on read from the
// persisted artifact + serializer, so nothing is lost.
type RetentionService struct {
	repo   Repository
	window time.Duration
	clock  Clock
}

// NewRetentionService wires the worker to prune delivered Publications older than window.
func NewRetentionService(repo Repository, window time.Duration, clock Clock) *RetentionService {
	return &RetentionService{repo: repo, window: window, clock: clock}
}

// Prune drops the payloads of delivered Publications recorded before now-window and returns
// how many were pruned.
func (s *RetentionService) Prune(ctx context.Context) (int, error) {
	return s.repo.PrunePayloads(ctx, s.clock.Now().Add(-s.window))
}
