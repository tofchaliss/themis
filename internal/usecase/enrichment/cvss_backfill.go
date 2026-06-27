package enrichment

import (
	"context"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

// CR-5 — CVSS backfill.
//
// apk/rpm findings correlated via OSV/distro feeds often arrive without CVSS, so
// they score 0 and can't be prioritised (D-CVSS-1). This service pulls the
// authoritative CVSS for those catalog rows from the NVD by-CVE endpoint, writes
// it back (which the catalog propagates into risk_context.raw_severity for unknown
// findings), and triggers a re-enrich so risk scores spread. CVEs the NVD has not
// scored yet are marked checked and retried only after a back-off.

const (
	defaultCVSSBackfillLimit      = 200
	defaultCVSSBackfillRetryAfter = 7 * 24 * time.Hour
	// maxConsecutiveCVSSFetchErrors aborts a cycle once NVD has failed this many
	// times in a row, so a sustained outage/throttle records one feed failure
	// instead of a per-CVE warning storm across the whole batch.
	maxConsecutiveCVSSFetchErrors = 8
)

// CVSSFetcher fetches a single CVE's CVSS verdict (implemented by the NVD client).
type CVSSFetcher interface {
	FetchByCVEID(ctx context.Context, cveID string) (domain.CVSSData, bool, error)
}

// CVSSCatalogStore reads backfill candidates and writes CVSS back to the catalog.
type CVSSCatalogStore interface {
	ListCVEsNeedingCVSS(ctx context.Context, limit int, before time.Time) ([]string, error)
	ApplyCVSS(ctx context.Context, cveID, severity string, score float64, vector string) error
	MarkCVSSChecked(ctx context.Context, cveID string) error
}

// CVSSReEnricher enqueues re-enrichment after backfill updates land.
type CVSSReEnricher interface {
	EnqueueReEnrichSignalsBatches(ctx context.Context, totalOpen int) error
}

// CVSSOpenFindingCounter counts open findings to size the re-enrich.
type CVSSOpenFindingCounter interface {
	CountOpenRiskContexts(ctx context.Context) (int, error)
}

// CVSSBackfillMetrics records per-CVE backfill outcomes.
type CVSSBackfillMetrics interface {
	RecordBackfill(status string) // "updated" | "checked" | "error"
}

// NoOpCVSSBackfillMetrics ignores backfill metrics.
type NoOpCVSSBackfillMetrics struct{}

// RecordBackfill discards the metric.
func (NoOpCVSSBackfillMetrics) RecordBackfill(string) {}

// CVSSBackfillService orchestrates the NVD-by-CVE CVSS backfill.
type CVSSBackfillService struct {
	Fetcher    CVSSFetcher
	Catalog    CVSSCatalogStore
	ReEnrich   CVSSReEnricher
	OpenCount  CVSSOpenFindingCounter
	Metrics    CVSSBackfillMetrics
	Logger     domain.Logger
	BatchLimit int
	RetryAfter time.Duration
	Now        func() time.Time
}

// CVSSBackfillResult summarizes a backfill cycle.
type CVSSBackfillResult struct {
	Candidates int
	Updated    int
	Checked    int
	Errors     int
}

// RunBackfill fetches CVSS for catalog rows that lack it, writes it back, and
// enqueues a re-enrich when any row was updated. A per-CVE fetch error is logged
// and skipped (retried next cycle); only store errors abort the cycle.
func (s *CVSSBackfillService) RunBackfill(ctx context.Context) (CVSSBackfillResult, error) {
	if s.Fetcher == nil || s.Catalog == nil {
		return CVSSBackfillResult{}, nil
	}
	log := domain.LoggerOrNop(s.Logger)
	metrics := s.metrics()
	before := s.now().Add(-s.retryAfter())

	cveIDs, err := s.Catalog.ListCVEsNeedingCVSS(ctx, s.batchLimit(), before)
	if err != nil {
		return CVSSBackfillResult{}, err
	}
	result := CVSSBackfillResult{Candidates: len(cveIDs)}
	consecutiveErrors := 0
	aborted := false
	for _, cveID := range cveIDs {
		data, found, fetchErr := s.Fetcher.FetchByCVEID(ctx, cveID)
		if fetchErr != nil {
			result.Errors++
			consecutiveErrors++
			metrics.RecordBackfill("error")
			log.Warn("cvss backfill fetch failed", domain.LogString("cve_id", cveID), domain.LogErr(fetchErr))
			if consecutiveErrors >= maxConsecutiveCVSSFetchErrors {
				aborted = true
				break
			}
			continue
		}
		consecutiveErrors = 0
		if found {
			if err := s.Catalog.ApplyCVSS(ctx, cveID, data.Severity, data.Score, data.Vector); err != nil {
				return result, err
			}
			result.Updated++
			metrics.RecordBackfill("updated")
			continue
		}
		if err := s.Catalog.MarkCVSSChecked(ctx, cveID); err != nil {
			return result, err
		}
		result.Checked++
		metrics.RecordBackfill("checked")
	}

	// Re-enrich any rows that did land before reporting an abort, so partial
	// progress is not lost.
	if result.Updated > 0 && s.ReEnrich != nil && s.OpenCount != nil {
		total, err := s.OpenCount.CountOpenRiskContexts(ctx)
		if err != nil {
			return result, err
		}
		if err := s.ReEnrich.EnqueueReEnrichSignalsBatches(ctx, total); err != nil {
			return result, err
		}
	}
	if aborted {
		return result, fmt.Errorf("cvss backfill aborted after %d consecutive NVD fetch failures (NVD unavailable or throttling)", consecutiveErrors)
	}
	log.Info("cvss backfill completed",
		domain.LogInt("candidates", result.Candidates),
		domain.LogInt("updated", result.Updated),
		domain.LogInt("checked", result.Checked),
		domain.LogInt("errors", result.Errors))
	return result, nil
}

func (s *CVSSBackfillService) metrics() CVSSBackfillMetrics {
	if s.Metrics == nil {
		return NoOpCVSSBackfillMetrics{}
	}
	return s.Metrics
}

func (s *CVSSBackfillService) batchLimit() int {
	if s.BatchLimit <= 0 {
		return defaultCVSSBackfillLimit
	}
	return s.BatchLimit
}

func (s *CVSSBackfillService) retryAfter() time.Duration {
	if s.RetryAfter <= 0 {
		return defaultCVSSBackfillRetryAfter
	}
	return s.RetryAfter
}

func (s *CVSSBackfillService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
