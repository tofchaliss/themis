package enrichment_test

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/testutil/gen"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// severityRankAscending lists severities whose risk scores never decrease as the
// index grows, for every effective state (factors are non-negative).
var severityRankAscending = []string{"none", "low", "medium", "high", "critical"}

func TestComputeRiskScoreProperty_Bounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := gen.AnySeverity(t)
		state := gen.AnyEffectiveState(t)
		score := enrichment.ComputeRiskScore(severity, state)
		if score < 0 || score > 100 {
			t.Fatalf("score %d out of range for severity=%q state=%q", score, severity, state)
		}
	})
}

func TestComputeRiskScoreProperty_MonotonicInSeverity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		state := gen.AnyEffectiveState(t)
		i := rapid.IntRange(0, len(severityRankAscending)-1).Draw(t, "low_rank")
		j := rapid.IntRange(i, len(severityRankAscending)-1).Draw(t, "high_rank")
		lo := enrichment.ComputeRiskScore(severityRankAscending[i], state)
		hi := enrichment.ComputeRiskScore(severityRankAscending[j], state)
		if lo > hi {
			t.Fatalf("non-monotonic: %s=%d > %s=%d for state=%q",
				severityRankAscending[i], lo, severityRankAscending[j], hi, state)
		}
	})
}

func TestComputeRiskScoreProperty_StateOrdering(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := gen.AnySeverity(t)
		detected := enrichment.ComputeRiskScore(severity, domain.EffectiveStateDetected)

		if got := enrichment.ComputeRiskScore(severity, domain.EffectiveStateResolved); got != 0 {
			t.Fatalf("resolved score = %d, want 0 (severity=%q)", got, severity)
		}
		for _, suppress := range []string{
			domain.EffectiveStateSuppressed,
			domain.EffectiveStateFalsePositive,
			domain.EffectiveStateAcceptedRisk,
		} {
			if got := enrichment.ComputeRiskScore(severity, suppress); got > detected {
				t.Fatalf("%s score %d exceeds detected %d (severity=%q)", suppress, got, detected, severity)
			}
		}
		if got := enrichment.ComputeRiskScore(severity, domain.EffectiveStateConfirmed); got < detected {
			t.Fatalf("confirmed score %d below detected %d (severity=%q)", got, detected, severity)
		}
	})
}

func TestComputeRiskScoreProperty_CaseInsensitive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := rapid.SampledFrom([]string{"critical", "high", "medium", "low", "none"}).Draw(t, "severity")
		state := rapid.SampledFrom([]string{
			domain.EffectiveStateDetected,
			domain.EffectiveStateSuppressed,
			domain.EffectiveStateConfirmed,
			domain.EffectiveStateAcceptedRisk,
			domain.EffectiveStateFalsePositive,
			domain.EffectiveStateResolved,
		}).Draw(t, "state")

		canonical := enrichment.ComputeRiskScore(severity, state)
		mixed := enrichment.ComputeRiskScore(gen.RandomCase(t, severity), gen.RandomCase(t, state))
		if canonical != mixed {
			t.Fatalf("case sensitivity: canonical=%d mixed=%d (severity=%q state=%q)",
				canonical, mixed, severity, state)
		}
		// Leading/trailing whitespace on severity must not change the score.
		padded := enrichment.ComputeRiskScore("  "+strings.ToUpper(severity)+"  ", state)
		if canonical != padded {
			t.Fatalf("whitespace sensitivity: canonical=%d padded=%d", canonical, padded)
		}
	})
}
