package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	redHatVEXOnce sync.Once

	// RedHatVEXTotal counts Red Hat Security Data API VEX-overlay verdict outcomes
	// per CVE (not_affected | fixed | affected | checked | error).
	RedHatVEXTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "themis_redhat_vex_total",
			Help: "Red Hat Security Data API VEX overlay verdict outcomes per CVE.",
		},
		[]string{"status"},
	)
)

// RegisterRedHatVEX installs Red Hat VEX overlay metrics.
func RegisterRedHatVEX() {
	redHatVEXOnce.Do(func() {
		prometheus.MustRegister(RedHatVEXTotal)
	})
}

// RedHatVEXMetrics implements enrichment.RedHatVEXMetrics.
type RedHatVEXMetrics struct{}

// RecordVerdict records one per-CVE verdict outcome.
func (RedHatVEXMetrics) RecordVerdict(status string) {
	RedHatVEXTotal.WithLabelValues(status).Inc()
}
