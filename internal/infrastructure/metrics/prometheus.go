package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "themis"

var (
	registerOnce sync.Once

	IngestionJobsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "ingestion_jobs_total",
			Help:      "Total ingestion jobs processed by outcome.",
		},
		[]string{"job_type", "status"},
	)

	JobDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "job_duration_seconds",
			Help:      "Ingestion job processing duration in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"job_type"},
	)

	QueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "queue_depth",
			Help:      "Number of jobs waiting in the in-process queue buffer.",
		},
	)

	ActiveWorkers = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_workers",
			Help:      "Number of worker goroutines currently processing jobs.",
		},
	)

	NotificationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "notifications_total",
			Help:      "Total notifications dispatched by channel and outcome.",
		},
		[]string{"channel_type", "status"},
	)

	CVEWatchCyclesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cve_watch_cycles_total",
			Help:      "Total CVE watch poll cycles by outcome.",
		},
		[]string{"status"},
	)

	CVEWatchDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "cve_watch_duration_seconds",
			Help:      "CVE watch poll cycle duration in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	CVEWatchNewFindingsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cve_watch_new_findings_total",
			Help:      "New component vulnerability findings created by CVE watch.",
		},
		[]string{"ecosystem"},
	)
)

// Register installs all Prometheus collectors. Safe to call multiple times.
func Register() {
	registerOnce.Do(func() {
		prometheus.MustRegister(
			IngestionJobsTotal,
			JobDurationSeconds,
			QueueDepth,
			ActiveWorkers,
			NotificationsTotal,
			CVEWatchCyclesTotal,
			CVEWatchDurationSeconds,
			CVEWatchNewFindingsTotal,
		)
	})
}

// RecordIngestionJob increments ingestion counters and observes duration.
func RecordIngestionJob(jobType, status string, duration time.Duration) {
	IngestionJobsTotal.WithLabelValues(jobType, status).Inc()
	JobDurationSeconds.WithLabelValues(jobType).Observe(duration.Seconds())
}

// SetQueueDepth updates the queue depth gauge.
func SetQueueDepth(depth int) {
	QueueDepth.Set(float64(depth))
}

// RecordNotification increments notification delivery counters.
func RecordNotification(channelType, status string) {
	NotificationsTotal.WithLabelValues(channelType, status).Inc()
}

// RecordCVEWatchCycle records a completed CVE watch cycle.
func RecordCVEWatchCycle(status string, duration time.Duration) {
	CVEWatchCyclesTotal.WithLabelValues(status).Inc()
	CVEWatchDurationSeconds.Observe(duration.Seconds())
}

// RecordCVEWatchNewFindings increments new finding counters for an ecosystem.
func RecordCVEWatchNewFindings(ecosystem string, count int) {
	if count <= 0 {
		return
	}
	CVEWatchNewFindingsTotal.WithLabelValues(ecosystem).Add(float64(count))
}
