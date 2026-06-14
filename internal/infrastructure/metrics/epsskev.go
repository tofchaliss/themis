package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	epssKevRegisterOnce sync.Once

	EPSSKevSyncTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "epsskev_sync_total",
			Help:      "Total EPSS/KEV sync attempts by feed and outcome.",
		},
		[]string{"feed", "status"},
	)

	EPSSKevStale = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "epsskev_stale",
			Help:      "Whether EPSS/KEV signals are stale (1) or fresh (0).",
		},
	)

	ReEnrichJobBatchesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "reenrichjob_batches_total",
			Help:      "Total ReEnrichJob batches enqueued after signal sync.",
		},
	)
)

// RegisterEPSSKev installs Phase 2a EPSS/KEV metrics.
func RegisterEPSSKev() {
	epssKevRegisterOnce.Do(func() {
		prometheus.MustRegister(EPSSKevSyncTotal, EPSSKevStale, ReEnrichJobBatchesTotal)
	})
}

// EPSSKevMetrics implements epsskev.SyncMetrics.
type EPSSKevMetrics struct{}

func (EPSSKevMetrics) RecordSync(feed, status string) {
	EPSSKevSyncTotal.WithLabelValues(feed, status).Inc()
}

func (EPSSKevMetrics) RecordReEnrichBatches(count int) {
	if count > 0 {
		ReEnrichJobBatchesTotal.Add(float64(count))
	}
}

func (EPSSKevMetrics) SetStale(stale bool) {
	if stale {
		EPSSKevStale.Set(1)
	} else {
		EPSSKevStale.Set(0)
	}
}
