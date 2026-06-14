package enrichment_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

func TestFormula_CriticalOverride(t *testing.T) {
	epss := 1.0
	got := enrichment.ComputeRiskScoreV2(
		"high",
		domain.EffectiveStateDetected,
		&epss,
		true,
		false,
		string(domain.DeterministicLevelCritical),
		2.0,
	)
	if got != 100 {
		t.Fatalf("score = %d, want 100", got)
	}
}

func TestFormula_NullEPSSIsZero(t *testing.T) {
	nullScore := enrichment.ComputeRiskScoreV2(
		"medium",
		domain.EffectiveStateDetected,
		nil,
		false,
		false,
		string(domain.DeterministicLevelInformational),
		1.0,
	)
	zero := 0.0
	zeroScore := enrichment.ComputeRiskScoreV2(
		"medium",
		domain.EffectiveStateDetected,
		&zero,
		false,
		false,
		string(domain.DeterministicLevelInformational),
		1.0,
	)
	if nullScore != zeroScore {
		t.Fatalf("NULL score = %d, zero score = %d", nullScore, zeroScore)
	}
}

func TestFormula_Suppressed(t *testing.T) {
	epss := 0.95
	got := enrichment.ComputeRiskScoreV2(
		"high",
		domain.EffectiveStateSuppressed,
		&epss,
		false,
		false,
		string(domain.DeterministicLevelInformational),
		1.5,
	)
	if got >= 30 {
		t.Fatalf("suppressed score = %d, want very low", got)
	}
}

func TestFormula_Resolved(t *testing.T) {
	epss := 1.0
	got := enrichment.ComputeRiskScoreV2(
		"critical",
		domain.EffectiveStateResolved,
		&epss,
		true,
		true,
		string(domain.DeterministicLevelCritical),
		2.0,
	)
	if got != 0 {
		t.Fatalf("resolved score = %d, want 0", got)
	}
}

func TestFormula_CapAt100(t *testing.T) {
	epss := 1.0
	got := enrichment.ComputeRiskScoreV2(
		"critical",
		domain.EffectiveStateDetected,
		&epss,
		true,
		false,
		string(domain.DeterministicLevelHigh),
		2.0,
	)
	if got != 100 {
		t.Fatalf("score = %d, want 100 cap", got)
	}
}

func TestFormula_KEVAdjustment(t *testing.T) {
	const (
		severity = "low"
		state    = domain.EffectiveStateDetected
		level    = domain.DeterministicLevelInformational
	)
	without := enrichment.ComputeRiskScoreV2(severity, state, nil, false, false, string(level), 1.0)
	with := enrichment.ComputeRiskScoreV2(severity, state, nil, true, false, string(level), 1.0)
	if with-without != domain.RiskScoreKEVAdjustment {
		t.Fatalf("KEV delta = %d, want %d (without=%d with=%d)", with-without, domain.RiskScoreKEVAdjustment, without, with)
	}
}

func TestFormula_EPSSAdjustment(t *testing.T) {
	const (
		severity = "low"
		state    = domain.EffectiveStateDetected
		level    = domain.DeterministicLevelInformational
	)
	base := float64(enrichment.ComputeRiskScore(severity, state))
	zero := 0.0
	one := 1.0
	without := enrichment.ComputeRiskScoreV2(severity, state, &zero, false, false, string(level), 1.0)
	with := enrichment.ComputeRiskScoreV2(severity, state, &one, false, false, string(level), 1.0)
	wantDelta := int(base * domain.RiskScoreEPSSMultiplierMax)
	if with-without != wantDelta {
		t.Fatalf("EPSS delta = %d, want %d (without=%d with=%d)", with-without, wantDelta, without, with)
	}
}

func TestFormula_HighScenarioFromSpec(t *testing.T) {
	epss := 0.8
	got := enrichment.ComputeRiskScoreV2(
		"high",
		domain.EffectiveStateDetected,
		&epss,
		false,
		false,
		string(domain.DeterministicLevelInformational),
		1.5,
	)
	if got != 100 {
		t.Fatalf("score = %d, want 100 (spec scenario)", got)
	}
}
