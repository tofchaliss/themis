package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

func TestPhase2aConstants(t *testing.T) {
	if domain.EffectiveStateNotAffected != "not_affected" {
		t.Fatalf("EffectiveStateNotAffected = %q", domain.EffectiveStateNotAffected)
	}
	if domain.JobTypeReEnrichSignals != "reenrich_signals" {
		t.Fatalf("JobTypeReEnrichSignals = %q", domain.JobTypeReEnrichSignals)
	}
	if domain.JobTypeSyncVEXFeed != "sync_vex_feed" {
		t.Fatalf("JobTypeSyncVEXFeed = %q", domain.JobTypeSyncVEXFeed)
	}
}

func TestComputeBlastRadiusScore(t *testing.T) {
	if domain.ComputeBlastRadiusScore(0) != domain.RiskScoreBlastRadiusMin {
		t.Fatalf("0 customers score = %v", domain.ComputeBlastRadiusScore(0))
	}
	if domain.ComputeBlastRadiusScore(1) != domain.RiskScoreBlastRadiusMin {
		t.Fatalf("1 customer score = %v", domain.ComputeBlastRadiusScore(1))
	}
	if domain.ComputeBlastRadiusScore(5) != 1.4 {
		t.Fatalf("5 customers score = %v", domain.ComputeBlastRadiusScore(5))
	}
	if domain.ComputeBlastRadiusScore(10) != 2.0 {
		t.Fatalf("10 customers score = %v", domain.ComputeBlastRadiusScore(10))
	}
}

func TestDeterministicLevels(t *testing.T) {
	levels := []domain.DeterministicLevel{
		domain.DeterministicLevelCritical,
		domain.DeterministicLevelHighPlus,
		domain.DeterministicLevelHigh,
		domain.DeterministicLevelElevated,
		domain.DeterministicLevelInformational,
	}
	for _, level := range levels {
		if level == "" {
			t.Fatal("empty deterministic level")
		}
	}
}

func TestUpstreamVEXCoverageValues(t *testing.T) {
	cases := []domain.UpstreamVEXCoverage{
		domain.UpstreamVEXCoverageCovered,
		domain.UpstreamVEXCoverageNotCovered,
		domain.UpstreamVEXCoveragePURLMismatch,
	}
	for _, c := range cases {
		if string(c) == "" {
			t.Fatal("empty upstream vex coverage")
		}
	}
}

func TestAssetGraphEntities(t *testing.T) {
	now := time.Now()
	ms := domain.Microservice{ID: "ms-1", ProductID: "p-1", Name: "api", CreatedAt: now}
	dep := domain.Deployment{ID: "d-1", MicroserviceID: ms.ID, CustomerID: "c-1", Environment: "prod"}
	customer := domain.Customer{ID: "c-1", Name: "Platform", ContactEmail: "platform@example.com"}
	record := domain.ExploitRecord{EDBID: "12345", CVEID: "CVE-2024-0001", Title: "demo"}

	if ms.Name != "api" || dep.Environment != "prod" || customer.ContactEmail == "" || record.EDBID == "" {
		t.Fatalf("unexpected entities: %+v %+v %+v %+v", ms, dep, customer, record)
	}
}

func TestRiskScorePhase2aConstants(t *testing.T) {
	if domain.RiskScoreKEVAdjustment != 15 {
		t.Fatalf("RiskScoreKEVAdjustment = %d", domain.RiskScoreKEVAdjustment)
	}
	if domain.RiskScoreBlastRadiusMax != 2.0 {
		t.Fatalf("RiskScoreBlastRadiusMax = %v", domain.RiskScoreBlastRadiusMax)
	}
}

func TestRiskContextSnapshotPhase2aFields(t *testing.T) {
	epss := 0.42
	snap := domain.RiskContextSnapshot{
		EPSSScore:           &epss,
		KEVListed:           true,
		ExploitPublic:       true,
		DeterministicLevel:  domain.DeterministicLevelCritical,
		BlastRadiusScore:    1.5,
		UpstreamVEXCoverage: domain.UpstreamVEXCoverageCovered,
	}
	if snap.DeterministicLevel != domain.DeterministicLevelCritical {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
}
