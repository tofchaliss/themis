package enrichment

// MetricsRecorder records Phase 2a enrichment observability counters. A nil
// recorder is tolerated by the handler (see recordMetrics), so no no-op
// implementation is needed.
type MetricsRecorder interface {
	RecordLayer1Rule(level string)
	RecordBlastRadiusScore(score float64)
	RecordPURLMismatch(feed string)
}
