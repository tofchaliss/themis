package enrichment_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

type signalStub struct {
	epss    map[string]float64
	kev     map[string]bool
	exploit map[string]bool
}

func (s signalStub) GetEPSSForCVE(_ context.Context, cveID string) (*float64, error) {
	if score, ok := s.epss[cveID]; ok {
		return &score, nil
	}
	return nil, nil
}

func (s signalStub) IsKEVListed(_ context.Context, cveID string) (bool, error) {
	return s.kev[cveID], nil
}

func (s signalStub) HasPublicExploit(_ context.Context, cveID string) (bool, error) {
	return s.exploit[cveID], nil
}

type reenrichRepo struct {
	rows      []domain.OpenRiskContextRow
	lastScore int
	lastKEV   bool
}

func (r *reenrichRepo) ListFindingsForArtifact(context.Context, string) ([]domain.EnrichmentFinding, error) {
	return nil, nil
}
func (r *reenrichRepo) ListAssertionsForArtifact(context.Context, string) ([]domain.VEXAssertionMatch, error) {
	return nil, nil
}
func (r *reenrichRepo) GetRiskContext(context.Context, string, string, string) (domain.RiskContextSnapshot, error) {
	return domain.RiskContextSnapshot{}, nil
}
func (r *reenrichRepo) UpsertRiskContext(context.Context, domain.EnrichmentFinding, domain.RiskContextSnapshot) error {
	return nil
}
func (r *reenrichRepo) ArtifactForVEX(context.Context, string) (string, error) { return "", nil }
func (r *reenrichRepo) CountOpenRiskContexts(context.Context) (int, error)         { return len(r.rows), nil }
func (r *reenrichRepo) ListOpenRiskContexts(_ context.Context, offset, limit int) ([]domain.OpenRiskContextRow, error) {
	if offset >= len(r.rows) {
		return nil, nil
	}
	end := offset + limit
	if end > len(r.rows) {
		end = len(r.rows)
	}
	return r.rows[offset:end], nil
}
func (r *reenrichRepo) UpdateRiskContextSignals(_ context.Context, row domain.OpenRiskContextRow, _ *float64, kev, exploit bool, _ domain.DeterministicLevel, score int) error {
	r.lastKEV = kev
	r.lastScore = score
	_ = exploit
	return nil
}

func TestComputeRiskScoreWithSignalsKEV(t *testing.T) {
	score := enrichment.ComputeRiskScoreWithSignals("low", domain.EffectiveStateDetected, nil, true)
	want := enrichment.ComputeRiskScoreV2(
		"low",
		domain.EffectiveStateDetected,
		nil,
		true,
		false,
		"",
		domain.RiskScoreBlastRadiusMin,
	)
	if score != want {
		t.Fatalf("score = %d, want %d", score, want)
	}
}

func TestReEnrichSignalsBatchExploitPublic(t *testing.T) {
	repo := &reenrichRepo{rows: []domain.OpenRiskContextRow{{
		ComponentPURL: "cv-1",
		CVEID:                    "CVE-2024-0001",
		RawSeverity:              "high",
		EffectiveState:           domain.EffectiveStateDetected,
		CVSSScore:                9.1,
	}}}
	handler := &enrichment.Handler{Repo: repo}
	err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, signalStub{
		exploit: map[string]bool{"CVE-2024-0001": true},
	})
	if err != nil {
		t.Fatalf("ReEnrichSignalsBatch() error = %v", err)
	}
}

func TestReEnrichSignalsBatchNilRepo(t *testing.T) {
	handler := &enrichment.Handler{}
	if err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, signalStub{}); err != nil {
		t.Fatal(err)
	}
}

type errSignalStub struct{}

func (errSignalStub) GetEPSSForCVE(context.Context, string) (*float64, error) {
	return nil, context.Canceled
}
func (errSignalStub) IsKEVListed(context.Context, string) (bool, error) { return false, nil }
func (errSignalStub) HasPublicExploit(context.Context, string) (bool, error) {
	return false, nil
}

func TestReEnrichSignalsBatchSignalError(t *testing.T) {
	repo := &reenrichRepo{rows: []domain.OpenRiskContextRow{{ComponentPURL: "cv-1", CVEID: "CVE-1", RawSeverity: "high", EffectiveState: domain.EffectiveStateDetected}}}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, errSignalStub{}); err == nil {
		t.Fatal("expected signal error")
	}
}

type errEPSSSignal struct{ errSignalStub }

func (errEPSSSignal) GetEPSSForCVE(context.Context, string) (*float64, error) {
	return nil, context.Canceled
}

func TestReEnrichSignalsBatchEPSSError(t *testing.T) {
	repo := &reenrichRepo{rows: []domain.OpenRiskContextRow{{ComponentPURL: "cv-1", CVEID: "CVE-1", RawSeverity: "high", EffectiveState: domain.EffectiveStateDetected}}}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, errEPSSSignal{}); err == nil {
		t.Fatal("expected epss error")
	}
}

type errKEVSignal struct{}

func (errKEVSignal) GetEPSSForCVE(context.Context, string) (*float64, error) { return nil, nil }
func (errKEVSignal) IsKEVListed(context.Context, string) (bool, error) {
	return false, context.Canceled
}
func (errKEVSignal) HasPublicExploit(context.Context, string) (bool, error) { return false, nil }

func TestReEnrichSignalsBatchKEVError(t *testing.T) {
	repo := &reenrichRepo{rows: []domain.OpenRiskContextRow{{ComponentPURL: "cv-1", CVEID: "CVE-1", RawSeverity: "high", EffectiveState: domain.EffectiveStateDetected}}}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, errKEVSignal{}); err == nil {
		t.Fatal("expected kev error")
	}
}

type errExploitSignal struct{}

func (errExploitSignal) GetEPSSForCVE(context.Context, string) (*float64, error) { return nil, nil }
func (errExploitSignal) IsKEVListed(context.Context, string) (bool, error)       { return false, nil }
func (errExploitSignal) HasPublicExploit(context.Context, string) (bool, error) {
	return false, context.Canceled
}

func TestReEnrichSignalsBatchExploitError(t *testing.T) {
	repo := &reenrichRepo{rows: []domain.OpenRiskContextRow{{ComponentPURL: "cv-1", CVEID: "CVE-1", RawSeverity: "high", EffectiveState: domain.EffectiveStateDetected}}}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, errExploitSignal{}); err == nil {
		t.Fatal("expected exploit error")
	}
}

type errUpdateRepo struct {
	*reenrichRepo
}

func (r *errUpdateRepo) UpdateRiskContextSignals(context.Context, domain.OpenRiskContextRow, *float64, bool, bool, domain.DeterministicLevel, int) error {
	return context.Canceled
}

func TestReEnrichSignalsBatchUpdateError(t *testing.T) {
	repo := &errUpdateRepo{reenrichRepo: &reenrichRepo{rows: []domain.OpenRiskContextRow{{ComponentPURL: "cv-1", CVEID: "CVE-1", RawSeverity: "high", EffectiveState: domain.EffectiveStateDetected}}}}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, signalStub{}); err == nil {
		t.Fatal("expected update error")
	}
}

type errListRepo struct {
	*reenrichRepo
}

func (r *errListRepo) ListOpenRiskContexts(context.Context, int, int) ([]domain.OpenRiskContextRow, error) {
	return nil, context.Canceled
}

func TestReEnrichSignalsBatchListError(t *testing.T) {
	repo := &errListRepo{reenrichRepo: &reenrichRepo{}}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, signalStub{}); err == nil {
		t.Fatal("expected list error")
	}
}

func TestReEnrichSignalsBatchNilSignals(t *testing.T) {
	repo := &reenrichRepo{rows: []domain.OpenRiskContextRow{{ComponentPURL: "cv-1", CVEID: "CVE-1", RawSeverity: "high", EffectiveState: domain.EffectiveStateDetected}}}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, nil); err != nil {
		t.Fatal(err)
	}
}

func TestReEnrichSignalsBatch(t *testing.T) {
	epss := 0.6
	repo := &reenrichRepo{rows: []domain.OpenRiskContextRow{{
		ComponentPURL: "cv-1",
		CVEID:                    "CVE-2024-0001",
		RawSeverity:              "high",
		EffectiveState:           domain.EffectiveStateDetected,
	}}}
	handler := &enrichment.Handler{Repo: repo}
	err := handler.ReEnrichSignalsBatch(context.Background(), 0, 500, signalStub{
		epss: map[string]float64{"CVE-2024-0001": epss},
		kev:  map[string]bool{"CVE-2024-0001": true},
	})
	if err != nil {
		t.Fatalf("ReEnrichSignalsBatch() error = %v", err)
	}
	if !repo.lastKEV || repo.lastScore < 85 {
		t.Fatalf("lastKEV=%v lastScore=%d", repo.lastKEV, repo.lastScore)
	}
}
