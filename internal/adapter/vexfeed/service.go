package vexfeed

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// AssertionStore persists upstream vendor VEX assertions.
type AssertionStore interface {
	UpsertAssertions(ctx context.Context, feed string, assertions []domain.VendorVEXAssertion) (int, error)
	ListAssertionsForCVE(ctx context.Context, cveID string) ([]domain.VendorVEXAssertion, error)
	ListAssertionsForSBOMCVEs(ctx context.Context, sbomDocumentID string, cveIDs []string) (map[string][]domain.VendorVEXAssertion, error)
	FindSBOMDocumentIDsForCVE(ctx context.Context, cveID string) ([]string, error)
}

// SBOMReEnqueuer schedules VEX overlay re-application for affected SBOMs.
type SBOMReEnqueuer interface {
	EnqueueApplyVEXForSBOMs(ctx context.Context, sbomDocumentIDs []string) error
}

// SyncLogger records vendor feed sync warnings and errors.
type SyncLogger interface {
	Warn(msg string, fields ...any)
	Error(msg string, fields ...any)
}

// NoOpSyncLogger ignores sync logs.
type NoOpSyncLogger struct{}

func (NoOpSyncLogger) Warn(string, ...any)  {}
func (NoOpSyncLogger) Error(string, ...any) {}

// SyncMetrics records vendor VEX sync counters.
type SyncMetrics interface {
	RecordSync(feed, status string)
	RecordAssertions(feed, matchType string, count int)
	RecordPURLMismatch(feed string)
}

// NoOpSyncMetrics ignores metrics.
type NoOpSyncMetrics struct{}

func (NoOpSyncMetrics) RecordSync(string, string)            {}
func (NoOpSyncMetrics) RecordAssertions(string, string, int) {}
func (NoOpSyncMetrics) RecordPURLMismatch(string)            {}

// FeedSource returns parsed vendor assertions for one feed.
type FeedSource interface {
	Fetch(ctx context.Context) ([]domain.VendorVEXAssertion, error)
	Name() string
}

// Service orchestrates vendor VEX feed sync cycles.
type Service struct {
	Feeds    []FeedSource
	Store    AssertionStore
	ReEnrich SBOMReEnqueuer
	Logger   SyncLogger
	Metrics  SyncMetrics
}

// SyncResult summarizes a vendor VEX sync run.
type SyncResult struct {
	AssertionsUpserted int
	SBOMsScheduled     int
}

// RunSync fetches all configured feeds, upserts assertions, and enqueues overlay re-runs.
func (s *Service) RunSync(ctx context.Context) (SyncResult, error) {
	if s.Store == nil {
		return SyncResult{}, nil
	}
	logger := s.Logger
	if logger == nil {
		logger = NoOpSyncLogger{}
	}
	metrics := s.Metrics
	if metrics == nil {
		metrics = NoOpSyncMetrics{}
	}

	var total int
	cveSet := map[string]struct{}{}
	for _, feed := range s.Feeds {
		if feed == nil {
			continue
		}
		name := feed.Name()
		assertions, err := feed.Fetch(ctx)
		if err != nil {
			metrics.RecordSync(name, "error")
			logger.Warn("vendor vex feed fetch failed", "feed", name, "error", err)
			continue
		}
		n, err := s.Store.UpsertAssertions(ctx, name, assertions)
		if err != nil {
			metrics.RecordSync(name, "error")
			return SyncResult{}, err
		}
		total += n
		metrics.RecordSync(name, "success")
		metrics.RecordAssertions(name, "upserted", n)
		for _, a := range assertions {
			cveSet[a.CVEID] = struct{}{}
		}
	}

	sbomSet := map[string]struct{}{}
	if s.ReEnrich != nil {
		for cveID := range cveSet {
			ids, err := s.Store.FindSBOMDocumentIDsForCVE(ctx, cveID)
			if err != nil {
				return SyncResult{AssertionsUpserted: total}, err
			}
			for _, id := range ids {
				sbomSet[id] = struct{}{}
			}
		}
		var sbomIDs []string
		for id := range sbomSet {
			sbomIDs = append(sbomIDs, id)
		}
		if err := s.ReEnrich.EnqueueApplyVEXForSBOMs(ctx, sbomIDs); err != nil {
			return SyncResult{AssertionsUpserted: total}, err
		}
	}

	return SyncResult{AssertionsUpserted: total, SBOMsScheduled: len(sbomSet)}, nil
}
