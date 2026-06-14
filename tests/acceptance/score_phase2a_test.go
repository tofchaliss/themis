package acceptance_test

import (
	"math"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/testutil/gen"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

var deterministicLevels = []string{
	string(domain.DeterministicLevelCritical),
	string(domain.DeterministicLevelHighPlus),
	string(domain.DeterministicLevelHigh),
	string(domain.DeterministicLevelElevated),
	string(domain.DeterministicLevelInformational),
	"",
}

func TestCompositeScoreOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := gen.AnySeverity(t)
		state := gen.AnyEffectiveState(t)
		level := rapid.SampledFrom(deterministicLevels).Draw(t, "deterministic_level")
		blast := rapid.Float64Range(0, 3).Draw(t, "blast_radius")
		kev := rapid.Bool().Draw(t, "kev")
		exploit := rapid.Bool().Draw(t, "exploit")
		var epss *float64
		switch rapid.IntRange(0, 2).Draw(t, "epss_kind") {
		case 1:
			v := rapid.Float64Range(0, 1).Draw(t, "epss")
			epss = &v
		case 2:
			zero := 0.0
			epss = &zero
		}

		score := enrichment.ComputeRiskScoreV2(severity, state, epss, kev, exploit, level, blast)
		if score < 0 || score > 100 {
			t.Fatalf("score %d out of range for severity=%q state=%q level=%q", score, severity, state, level)
		}
	})
}

func TestDeterministicCriticalAlwaysMax(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := gen.AnySeverity(t)
		state := gen.AnyEffectiveState(t)
		if state == domain.EffectiveStateResolved {
			return
		}
		base := float64(enrichment.ComputeRiskScore(severity, state))
		if base == 0 {
			return
		}
		blast := rapid.Float64Range(0, 3).Draw(t, "blast_radius")
		kev := rapid.Bool().Draw(t, "kev")
		exploit := rapid.Bool().Draw(t, "exploit")
		var epss *float64
		if rapid.Bool().Draw(t, "has_epss") {
			v := rapid.Float64Range(0, 1).Draw(t, "epss")
			epss = &v
		}

		score := enrichment.ComputeRiskScoreV2(
			severity,
			state,
			epss,
			kev,
			exploit,
			string(domain.DeterministicLevelCritical),
			blast,
		)
		if score != 100 {
			t.Fatalf("Critical level score = %d, want 100 (severity=%q state=%q)", score, severity, state)
		}
	})
}

func TestSuppressionIsMonotonicallyDecreasing(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := rapid.SampledFrom([]string{"critical", "high", "medium", "low"}).Draw(t, "severity")
		level := rapid.SampledFrom(deterministicLevels).Draw(t, "deterministic_level")
		if level == string(domain.DeterministicLevelCritical) {
			return
		}
		blast := rapid.Float64Range(1, 2).Draw(t, "blast_radius")
		kev := rapid.Bool().Draw(t, "kev")
		exploit := rapid.Bool().Draw(t, "exploit")
		var epss *float64
		if rapid.Bool().Draw(t, "has_epss") {
			v := rapid.Float64Range(0, 1).Draw(t, "epss")
			epss = &v
		}

		detected := enrichment.ComputeRiskScoreV2(severity, domain.EffectiveStateDetected, epss, kev, exploit, level, blast)
		suppressed := enrichment.ComputeRiskScoreV2(severity, domain.EffectiveStateSuppressed, epss, kev, exploit, level, blast)
		if suppressed >= detected {
			t.Fatalf("suppressed %d not below detected %d (severity=%q)", suppressed, detected, severity)
		}
	})
}

func TestEPSSAdjustmentBounds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := rapid.SampledFrom([]string{"critical", "high", "medium", "low"}).Draw(t, "severity")
		state := rapid.SampledFrom([]string{
			domain.EffectiveStateDetected,
			domain.EffectiveStateInTriage,
			domain.EffectiveStateConfirmed,
		}).Draw(t, "state")
		base := float64(enrichment.ComputeRiskScore(severity, state))
		if base <= 0 {
			return
		}
		epss := rapid.Float64Range(0, 1).Draw(t, "epss")
		level := rapid.SampledFrom(deterministicLevels).Draw(t, "deterministic_level")
		if level == string(domain.DeterministicLevelCritical) {
			return
		}

		zero := 0.0
		withZero := enrichment.ComputeRiskScoreV2(severity, state, &zero, false, false, level, 1.0)
		withEPSS := enrichment.ComputeRiskScoreV2(severity, state, &epss, false, false, level, 1.0)
		if withZero == withEPSS {
			return
		}

		delta := withEPSS - withZero
		minDelta := int(math.Floor(base * epss * domain.RiskScoreEPSSMultiplierMax))
		maxDelta := int(math.Ceil(base * epss * domain.RiskScoreEPSSMultiplierMax))
		if delta < minDelta || delta > maxDelta {
			t.Fatalf("EPSS delta %d outside [%d,%d] for base=%v epss=%v", delta, minDelta, maxDelta, base, epss)
		}
	})
}

func TestFormulaIsDeterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		severity := gen.AnySeverity(t)
		state := gen.AnyEffectiveState(t)
		level := rapid.SampledFrom(deterministicLevels).Draw(t, "deterministic_level")
		blast := rapid.Float64Range(0, 2).Draw(t, "blast_radius")
		kev := rapid.Bool().Draw(t, "kev")
		exploit := rapid.Bool().Draw(t, "exploit")
		var epss *float64
		if rapid.Bool().Draw(t, "has_epss") {
			v := rapid.Float64Range(0, 1).Draw(t, "epss")
			epss = &v
		}

		first := enrichment.ComputeRiskScoreV2(severity, state, epss, kev, exploit, level, blast)
		second := enrichment.ComputeRiskScoreV2(severity, state, epss, kev, exploit, level, blast)
		if first != second {
			t.Fatalf("non-deterministic score: first=%d second=%d", first, second)
		}
	})
}
