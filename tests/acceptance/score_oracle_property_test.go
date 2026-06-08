package acceptance_test

import (
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/testutil/gen"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/triage"
)

// TestRiskScoreOracleProperty guards against drift between the two independent
// ComputeRiskScore implementations (enrichment and triage). They must agree for
// every severity/state pair.
func TestRiskScoreOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := gen.AnySeverity(t)
		state := gen.AnyEffectiveState(t)
		got := enrichment.ComputeRiskScore(severity, state)
		want := triage.ComputeRiskScore(severity, state)
		if got != want {
			t.Fatalf("score drift for severity=%q state=%q: enrichment=%d triage=%d",
				severity, state, got, want)
		}
	})
}
