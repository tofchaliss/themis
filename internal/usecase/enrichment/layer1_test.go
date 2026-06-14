package enrichment_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

func floatPtr(v float64) *float64 { return &v }

func TestRule_CriticalKEV(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 9.1, KEVListed: true,
	})
	if got != domain.DeterministicLevelCritical {
		t.Fatalf("got %q, want Critical", got)
	}
}

func TestRule_CriticalExploit(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 9.1, ExploitPublic: true,
	})
	if got != domain.DeterministicLevelHighPlus {
		t.Fatalf("got %q, want High+", got)
	}
}

func TestRule_HighKEVLowCVSS(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 5.0, KEVListed: true,
	})
	if got != domain.DeterministicLevelHigh {
		t.Fatalf("got %q, want High", got)
	}
}

func TestRule_ElevatedEPSS(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 7.5, EPSSScore: floatPtr(0.6),
	})
	if got != domain.DeterministicLevelElevated {
		t.Fatalf("got %q, want Elevated", got)
	}
}

func TestRule_HighFloor(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 9.1,
	})
	if got != domain.DeterministicLevelHigh {
		t.Fatalf("got %q, want High", got)
	}
}

func TestRule_Informational(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 4.0,
	})
	if got != domain.DeterministicLevelInformational {
		t.Fatalf("got %q, want Informational", got)
	}
}

func TestRule_BoundaryCVSS9_0(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 9.0,
	})
	if got != domain.DeterministicLevelHigh {
		t.Fatalf("got %q, want High", got)
	}
}

func TestRule_BoundaryCVSS8_9(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 8.9, KEVListed: true,
	})
	if got != domain.DeterministicLevelHigh {
		t.Fatalf("got %q, want High", got)
	}
}

func TestRule_EPSS_0_499(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 7.0, EPSSScore: floatPtr(0.499),
	})
	if got != domain.DeterministicLevelInformational {
		t.Fatalf("got %q, want Informational", got)
	}
}

func TestRule_EPSS_0_5(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 7.0, EPSSScore: floatPtr(0.5),
	})
	if got != domain.DeterministicLevelElevated {
		t.Fatalf("got %q, want Elevated", got)
	}
}

func TestRule_AllSignals(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 9.5, KEVListed: true, ExploitPublic: true, EPSSScore: floatPtr(0.9),
	})
	if got != domain.DeterministicLevelCritical {
		t.Fatalf("got %q, want Critical", got)
	}
}

func TestRule_NullEPSS(t *testing.T) {
	got := enrichment.ComputeDeterministicLevel(enrichment.Layer1Input{
		CVSSScore: 7.0, EPSSScore: nil,
	})
	if got != domain.DeterministicLevelInformational {
		t.Fatalf("got %q, want Informational", got)
	}
}

func TestNoOpLayer3(t *testing.T) {
	var layer enrichment.NoOpLayer3
	if err := layer.Enrich(context.Background(), domain.EnrichmentFinding{}); err != nil {
		t.Fatal(err)
	}
}

func TestCVSSFromSeverity(t *testing.T) {
	cases := map[string]float64{
		"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 1.0, "unknown": 0,
	}
	for severity, want := range cases {
		if got := enrichment.CVSSFromSeverity(severity); got != want {
			t.Fatalf("%s: got %v want %v", severity, got, want)
		}
	}
}

func TestResolveCVSSScorePrefersFindingScore(t *testing.T) {
	got := enrichment.ResolveCVSSScore(domain.EnrichmentFinding{
		RawSeverity: "low",
		CVSSScore:   9.1,
	})
	if got != 9.1 {
		t.Fatalf("got %v", got)
	}
}

func TestHandlerUsesDefaultLayer3(t *testing.T) {
	repo := &layer3Repo{}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
}

type layer3ErrStub struct{}

func (layer3ErrStub) Enrich(context.Context, domain.EnrichmentFinding) error {
	return context.Canceled
}

func TestApplyVEXLayer3Error(t *testing.T) {
	repo := &layer3Repo{}
	handler := &enrichment.Handler{Repo: repo, Layer3: layer3ErrStub{}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err == nil {
		t.Fatal("expected layer3 error")
	}
}

func TestHandlerUsesCustomLayer3(t *testing.T) {
	called := false
	repo := &layer3Repo{}
	handler := &enrichment.Handler{
		Repo: repo,
		Layer3: layer3Stub{fn: func() { called = true }},
	}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected layer3 enrich to run")
	}
}

type layer3Stub struct {
	fn func()
}

func (s layer3Stub) Enrich(context.Context, domain.EnrichmentFinding) error {
	if s.fn != nil {
		s.fn()
	}
	return nil
}

type layer3Repo struct {
	findings []domain.EnrichmentFinding
}

func (r *layer3Repo) ListFindingsForSBOM(context.Context, string) ([]domain.EnrichmentFinding, error) {
	if len(r.findings) > 0 {
		return r.findings, nil
	}
	return []domain.EnrichmentFinding{{
		ComponentVulnerabilityID: "cv-1",
		ComponentPURL:          "pkg:npm/a@1.0.0",
		CVEID:                  "CVE-2024-0001",
		RawSeverity:            "high",
		CVSSScore:              7.5,
	}}, nil
}
func (r *layer3Repo) ListAssertionsForSBOM(context.Context, string) ([]domain.VEXAssertionMatch, error) {
	return nil, nil
}
func (r *layer3Repo) GetRiskContext(context.Context, string) (domain.RiskContextSnapshot, error) {
	return domain.RiskContextSnapshot{}, nil
}
func (r *layer3Repo) UpsertRiskContext(context.Context, domain.EnrichmentFinding, domain.RiskContextSnapshot) error {
	return nil
}
func (r *layer3Repo) SBOMDocumentForVEX(context.Context, string) (string, error) { return "", nil }
func (r *layer3Repo) CountOpenRiskContexts(context.Context) (int, error)           { return 0, nil }
func (r *layer3Repo) ListOpenRiskContexts(context.Context, int, int) ([]domain.OpenRiskContextRow, error) {
	return nil, nil
}
func (r *layer3Repo) UpdateRiskContextSignals(context.Context, domain.OpenRiskContextRow, *float64, bool, bool, domain.DeterministicLevel, int) error {
	return nil
}
