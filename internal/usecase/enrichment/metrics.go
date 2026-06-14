package enrichment

// MetricsRecorder records Phase 2a enrichment observability counters.
type MetricsRecorder interface {
	RecordLayer1Rule(level string)
	RecordBlastRadiusScore(score float64)
	RecordPURLMismatch(feed string)
}

// NoOpMetricsRecorder ignores enrichment metrics.
type NoOpMetricsRecorder struct{}

func (NoOpMetricsRecorder) RecordLayer1Rule(string)           {}
func (NoOpMetricsRecorder) RecordBlastRadiusScore(float64)    {}
func (NoOpMetricsRecorder) RecordPURLMismatch(string)         {}
