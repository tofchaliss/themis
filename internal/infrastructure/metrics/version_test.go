package metrics_test

import (
	"testing"

	"github.com/themis-project/themis/internal/infrastructure/metrics"
)

func TestName(t *testing.T) {
	if metrics.Name() != "metrics" {
		t.Fatalf("Name() = %q, want metrics", metrics.Name())
	}
}
