package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	vexFeedRegisterOnce sync.Once

	VEXFeedSyncTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "vexfeed_sync_total",
			Help:      "Total upstream vendor VEX feed sync attempts by feed and outcome.",
		},
		[]string{"feed", "status"},
	)

	VEXFeedAssertionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "vexfeed_assertions_total",
			Help:      "Vendor VEX assertions processed during sync by feed and match type.",
		},
		[]string{"feed", "match_type"},
	)

	VEXFeedPURLMismatchTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "vexfeed_purl_mismatch_total",
			Help:      "PURL mismatch events when four-phase vendor VEX matching fails.",
		},
		[]string{"feed"},
	)
)

// RegisterVEXFeed installs Phase 2a vendor VEX feed metrics.
func RegisterVEXFeed() {
	vexFeedRegisterOnce.Do(func() {
		prometheus.MustRegister(VEXFeedSyncTotal, VEXFeedAssertionsTotal, VEXFeedPURLMismatchTotal)
	})
}

// VEXFeedMetrics implements vexfeed.SyncMetrics and enrichment PURL mismatch recording.
type VEXFeedMetrics struct{}

func (VEXFeedMetrics) RecordSync(feed, status string) {
	VEXFeedSyncTotal.WithLabelValues(feed, status).Inc()
}

func (VEXFeedMetrics) RecordAssertions(feed, matchType string, count int) {
	if count > 0 {
		VEXFeedAssertionsTotal.WithLabelValues(feed, matchType).Add(float64(count))
	}
}

func (VEXFeedMetrics) RecordPURLMismatch(feed string) {
	if feed == "" {
		feed = "unknown"
	}
	VEXFeedPURLMismatchTotal.WithLabelValues(feed).Inc()
}
