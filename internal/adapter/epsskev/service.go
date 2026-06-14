package epsskev

import (
	"context"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

const (
	defaultReEnrichBatchSize = 500
	defaultMinEPSSRowRatio   = 0.5
	defaultStaleAfter        = 25 * time.Hour
)

// ReEnrichEnqueuer schedules signal re-enrichment batches.
type ReEnrichEnqueuer interface {
	EnqueueReEnrichSignalsBatches(ctx context.Context, totalOpen int) error
}

// SyncMetrics records EPSS/KEV sync outcomes.
type SyncMetrics interface {
	RecordSync(feed, status string)
	RecordReEnrichBatches(count int)
	SetStale(stale bool)
}

// NoOpMetrics ignores sync metrics.
type NoOpMetrics struct{}

func (NoOpMetrics) RecordSync(string, string) {}
func (NoOpMetrics) RecordReEnrichBatches(int) {}
func (NoOpMetrics) SetStale(bool)             {}

// Service orchestrates EPSS/KEV sync cycles.
type Service struct {
	Fetcher      domain.ThreatSignalFetcher
	Store        domain.ThreatSignalStore
	ReEnrich     ReEnrichEnqueuer
	OpenFindings OpenFindingCounter
	Metrics      SyncMetrics
	Now          func() time.Time
	BatchSize    int
	MinRowRatio  float64
	StaleAfter   time.Duration
}

// OpenFindingCounter counts open risk_context rows eligible for re-enrichment.
type OpenFindingCounter interface {
	CountOpenRiskContexts(ctx context.Context) (int, error)
}

// SyncResult summarizes a completed sync cycle.
type SyncResult struct {
	EPSSRows int
	KEVRows  int
}

// RunSync fetches feeds, upserts signals, and enqueues re-enrichment batches.
func (s *Service) RunSync(ctx context.Context) (SyncResult, error) {
	if s.Fetcher == nil || s.Store == nil {
		return SyncResult{}, fmt.Errorf("epsskev sync dependencies unavailable")
	}
	metrics := s.Metrics
	if metrics == nil {
		metrics = NoOpMetrics{}
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}

	epssSignals, err := s.Fetcher.FetchEPSS(ctx)
	if err != nil {
		metrics.RecordSync("epss", "error")
		s.refreshStale(ctx, now)
		return SyncResult{}, err
	}
	prevCount, err := s.Store.CountEPSSRows(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	if prevCount > 0 && float64(len(epssSignals)) < float64(prevCount)*s.minRowRatio() {
		metrics.RecordSync("epss", "aborted")
		return SyncResult{}, fmt.Errorf("epss csv truncated: got %d rows, previous %d", len(epssSignals), prevCount)
	}
	if err := s.Store.UpsertEPSS(ctx, epssSignals); err != nil {
		metrics.RecordSync("epss", "error")
		return SyncResult{}, err
	}
	metrics.RecordSync("epss", "success")

	kevSignals, err := s.Fetcher.FetchKEV(ctx)
	if err != nil {
		metrics.RecordSync("kev", "error")
		s.refreshStale(ctx, now)
		return SyncResult{EPSSRows: len(epssSignals)}, err
	}
	if err := s.Store.UpsertKEV(ctx, kevSignals); err != nil {
		metrics.RecordSync("kev", "error")
		return SyncResult{EPSSRows: len(epssSignals)}, err
	}
	metrics.RecordSync("kev", "success")

	if err := s.Store.MarkStale(ctx, false); err != nil {
		return SyncResult{EPSSRows: len(epssSignals), KEVRows: len(kevSignals)}, err
	}
	metrics.SetStale(false)

	if s.ReEnrich != nil && s.OpenFindings != nil {
		total, err := s.OpenFindings.CountOpenRiskContexts(ctx)
		if err != nil {
			return SyncResult{EPSSRows: len(epssSignals), KEVRows: len(kevSignals)}, err
		}
		if err := s.ReEnrich.EnqueueReEnrichSignalsBatches(ctx, total); err != nil {
			return SyncResult{EPSSRows: len(epssSignals), KEVRows: len(kevSignals)}, err
		}
		batches := batchCount(total, s.batchSize())
		metrics.RecordReEnrichBatches(batches)
	}

	return SyncResult{EPSSRows: len(epssSignals), KEVRows: len(kevSignals)}, nil
}

// RefreshStaleFlags marks signals stale when sync is overdue.
func (s *Service) RefreshStaleFlags(ctx context.Context) error {
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	s.refreshStale(ctx, now)
	return nil
}

func (s *Service) refreshStale(ctx context.Context, now time.Time) {
	if s.Store == nil {
		return
	}
	last, err := s.Store.LastSuccessfulFetch(ctx)
	if err != nil || last.IsZero() {
		return
	}
	if now.Sub(last) >= s.staleAfter() {
		_ = s.Store.MarkStale(ctx, true)
		if s.Metrics != nil {
			s.Metrics.SetStale(true)
		}
	}
}

func (s *Service) batchSize() int {
	if s.BatchSize <= 0 {
		return defaultReEnrichBatchSize
	}
	return s.BatchSize
}

func (s *Service) minRowRatio() float64 {
	if s.MinRowRatio <= 0 {
		return defaultMinEPSSRowRatio
	}
	return s.MinRowRatio
}

func (s *Service) staleAfter() time.Duration {
	if s.StaleAfter <= 0 {
		return defaultStaleAfter
	}
	return s.StaleAfter
}

func batchCount(total, batchSize int) int {
	if total <= 0 {
		return 0
	}
	return (total + batchSize - 1) / batchSize
}
