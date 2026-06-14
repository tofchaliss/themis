package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	enrichmentRegisterOnce sync.Once

	Layer1RulesFiredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "layer1_rules_fired_total",
			Help:      "Layer 1 deterministic rule outcomes by level.",
		},
		[]string{"level"},
	)

	BlastRadiusScore = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "blast_radius_score",
			Help:      "Blast-radius score multiplier written during enrichment.",
			Buckets:   []float64{1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0},
		},
	)
)

// RegisterEnrichment installs Phase 2a enrichment metrics.
func RegisterEnrichment() {
	enrichmentRegisterOnce.Do(func() {
		prometheus.MustRegister(Layer1RulesFiredTotal, BlastRadiusScore)
	})
}

// RegisterPhase2a registers all Phase 2a Prometheus collectors.
func RegisterPhase2a() {
	RegisterEPSSKev()
	RegisterVEXFeed()
	RegisterEnrichment()
}

// EnrichmentMetrics implements enrichment.MetricsRecorder.
type EnrichmentMetrics struct{}

func (EnrichmentMetrics) RecordLayer1Rule(level string) {
	if level == "" {
		level = "unknown"
	}
	Layer1RulesFiredTotal.WithLabelValues(level).Inc()
}

func (EnrichmentMetrics) RecordBlastRadiusScore(score float64) {
	BlastRadiusScore.Observe(score)
}

func (EnrichmentMetrics) RecordPURLMismatch(feed string) {
	VEXFeedMetrics{}.RecordPURLMismatch(feed)
}
