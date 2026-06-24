package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	cvssBackfillOnce sync.Once

	// CVSSBackfillTotal counts NVD-by-CVE CVSS backfill outcomes (CR-5).
	CVSSBackfillTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "themis_cvss_backfill_total",
			Help: "NVD-by-CVE CVSS backfill outcomes per CVE.",
		},
		[]string{"status"},
	)
)

// RegisterCVSSBackfill installs CVSS backfill metrics.
func RegisterCVSSBackfill() {
	cvssBackfillOnce.Do(func() {
		prometheus.MustRegister(CVSSBackfillTotal)
	})
}

// CVSSBackfillMetrics implements enrichment.CVSSBackfillMetrics.
type CVSSBackfillMetrics struct{}

// RecordBackfill records one per-CVE backfill outcome ("updated"|"checked"|"error").
func (CVSSBackfillMetrics) RecordBackfill(status string) {
	CVSSBackfillTotal.WithLabelValues(status).Inc()
}
