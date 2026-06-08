package metrics_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/infrastructure/metrics"
)

func TestWatchRecorder(t *testing.T) {
	metrics.Register()
	rec := metrics.WatchRecorder{}
	rec.RecordCycle("success", time.Second)
	rec.RecordNewFindings("npm", 2)
	rec.RecordNewFindings("npm", 0)
}
