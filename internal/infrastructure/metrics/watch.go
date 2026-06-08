package metrics

import "time"

// WatchRecorder implements domain.WatchMetricsRecorder using Prometheus.
type WatchRecorder struct{}

// RecordCycle records CVE watch cycle outcome and duration.
func (WatchRecorder) RecordCycle(status string, duration time.Duration) {
	RecordCVEWatchCycle(status, duration)
}

// RecordNewFindings increments new finding counters for an ecosystem.
func (WatchRecorder) RecordNewFindings(ecosystem string, count int) {
	RecordCVEWatchNewFindings(ecosystem, count)
}
