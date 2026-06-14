package enrichment_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

type captureMetrics struct {
	level string
	score float64
	feed  string
}

func (c *captureMetrics) RecordLayer1Rule(level string)        { c.level = level }
func (c *captureMetrics) RecordBlastRadiusScore(score float64) { c.score = score }
func (c *captureMetrics) RecordPURLMismatch(feed string)       { c.feed = feed }

type stubVendorMatcher struct {
	result enrichment.VendorMatchResult
}

func (s stubVendorMatcher) Match(string, string, []domain.VendorVEXAssertion) enrichment.VendorMatchResult {
	return s.result
}

type stubVendorReader struct {
	assertions []domain.VendorVEXAssertion
}

func (s stubVendorReader) ListVendorAssertionsForCVE(context.Context, string) ([]domain.VendorVEXAssertion, error) {
	return s.assertions, nil
}

func TestApplyVEXRecordsMetricsOnVendorPURLMismatch(t *testing.T) {
	metrics := &captureMetrics{}
	repo := &memoryRepo{
		findings: []domain.EnrichmentFinding{{
			ComponentVulnerabilityID: "finding-1",
			ComponentPURL:            "pkg:rpm/rhel/httpd@1.0",
			CVEID:                    "CVE-2024-0001",
			RawSeverity:              "high",
			CVSSScore:                7.5,
		}},
		existing: map[string]domain.RiskContextSnapshot{
			"finding-1": {EPSSScore: ptrFloat(0.2), KEVListed: true},
		},
	}
	handler := &enrichment.Handler{
		Repo:    repo,
		Metrics: metrics,
		VendorVEX: stubVendorReader{assertions: []domain.VendorVEXAssertion{{
			Feed: "rhel", CVEID: "CVE-2024-0001", ComponentPURL: "pkg:rpm/debian/httpd@9",
		}}},
		VendorMatch: stubVendorMatcher{result: enrichment.VendorMatchResult{PURLMismatch: true}},
	}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
	if metrics.level == "" || metrics.score == 0 || metrics.feed != "rhel" {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func ptrFloat(v float64) *float64 { return &v }

func TestApplyVEXCreatesDetectedRiskContext(t *testing.T) {
	repo := &memoryRepo{
		findings: []domain.EnrichmentFinding{{
			ComponentVulnerabilityID: "finding-1",
			ComponentPURL:            "pkg:npm/lodash@1.0.0",
			CVEID:                    "CVE-2024-0001",
			RawSeverity:              "high",
		}},
	}
	handler := &enrichment.Handler{Repo: repo, Audit: &memoryAudit{}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
	if repo.upserts[0].EffectiveState != domain.EffectiveStateDetected {
		t.Fatalf("state = %q", repo.upserts[0].EffectiveState)
	}
	if repo.upserts[0].RiskScore != enrichment.ComputeRiskScoreV2(
		"high",
		domain.EffectiveStateDetected,
		nil,
		false,
		false,
		string(domain.DeterministicLevelInformational),
		domain.RiskScoreBlastRadiusMin,
	) {
		t.Fatalf("score = %d", repo.upserts[0].RiskScore)
	}
}

func TestApplyVEXSuppressesWithNotAffectedAssertion(t *testing.T) {
	now := time.Now()
	repo := &memoryRepo{
		findings: []domain.EnrichmentFinding{{
			ComponentVulnerabilityID: "finding-1",
			ComponentPURL:            "pkg:npm/lodash@1.0.0",
			CVEID:                    "CVE-2024-0001",
			RawSeverity:              "high",
		}},
		assertions: []domain.VEXAssertionMatch{{
			ID:            "assert-1",
			VEXDocumentID: "vex-1",
			ComponentPURL: "pkg:npm/lodash@1.0.0",
			CVEID:         "CVE-2024-0001",
			Status:        domain.VEXStatusNotAffected,
			Justification: "code_not_reachable",
			DocumentTime:  now,
		}},
	}
	audit := &memoryAudit{}
	handler := &enrichment.Handler{Repo: repo, Audit: audit}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
	if repo.upserts[0].EffectiveState != domain.EffectiveStateSuppressed {
		t.Fatalf("state = %q", repo.upserts[0].EffectiveState)
	}
	if repo.upserts[0].RiskScore != enrichment.ComputeRiskScoreV2(
		"high",
		domain.EffectiveStateSuppressed,
		nil,
		false,
		false,
		string(domain.DeterministicLevelInformational),
		domain.RiskScoreBlastRadiusMin,
	) {
		t.Fatalf("score = %d", repo.upserts[0].RiskScore)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d", len(audit.entries))
	}
}

func TestApplyVEXConfirmedAndResolvedTransitions(t *testing.T) {
	now := time.Now()
	repo := &memoryRepo{
		findings: []domain.EnrichmentFinding{
			{ComponentVulnerabilityID: "f1", ComponentPURL: "pkg:a@1", CVEID: "CVE-1", RawSeverity: "critical"},
			{ComponentVulnerabilityID: "f2", ComponentPURL: "pkg:b@1", CVEID: "CVE-2", RawSeverity: "medium"},
		},
		assertions: []domain.VEXAssertionMatch{
			{VEXDocumentID: "vex-1", ComponentPURL: "pkg:a@1", CVEID: "CVE-1", Status: domain.VEXStatusAffected, DocumentTime: now},
			{VEXDocumentID: "vex-1", ComponentPURL: "pkg:b@1", CVEID: "CVE-2", Status: domain.VEXStatusFixed, DocumentTime: now},
		},
	}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
	if repo.upserts[0].EffectiveState != domain.EffectiveStateConfirmed || repo.upserts[0].RiskScore != 100 {
		t.Fatalf("confirmed = %+v", repo.upserts[0])
	}
	if repo.upserts[1].EffectiveState != domain.EffectiveStateResolved || repo.upserts[1].RiskScore != 0 {
		t.Fatalf("resolved = %+v", repo.upserts[1])
	}
}

func TestApplyVEXMostRecentAssertionWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	repo := &memoryRepo{
		findings: []domain.EnrichmentFinding{{
			ComponentVulnerabilityID: "finding-1",
			ComponentPURL:            "pkg:npm/lodash@1.0.0",
			CVEID:                    "CVE-2024-0001",
			RawSeverity:              "high",
		}},
		assertions: []domain.VEXAssertionMatch{
			{VEXDocumentID: "vex-old", ComponentPURL: "pkg:npm/lodash@1.0.0", CVEID: "CVE-2024-0001", Status: domain.VEXStatusNotAffected, DocumentTime: older},
			{VEXDocumentID: "vex-new", ComponentPURL: "pkg:npm/lodash@1.0.0", CVEID: "CVE-2024-0001", Status: domain.VEXStatusUnderInvestigation, DocumentTime: newer},
		},
		existing: map[string]domain.RiskContextSnapshot{
			"finding-1": {EffectiveState: domain.EffectiveStateSuppressed, RawSeverity: "high"},
		},
	}
	audit := &memoryAudit{}
	handler := &enrichment.Handler{Repo: repo, Audit: audit}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
	if repo.upserts[0].EffectiveState != domain.EffectiveStateDetected {
		t.Fatalf("state = %q", repo.upserts[0].EffectiveState)
	}
	if len(audit.entries) != 1 || audit.entries[0].Details["trigger"] != "vex_applied" {
		t.Fatalf("audit = %+v", audit.entries)
	}
}

func TestApplyVEXRevokesToDetected(t *testing.T) {
	repo := &memoryRepo{
		findings: []domain.EnrichmentFinding{{
			ComponentVulnerabilityID: "finding-1",
			ComponentPURL:            "pkg:npm/lodash@1.0.0",
			CVEID:                    "CVE-2024-0001",
			RawSeverity:              "high",
		}},
		existing: map[string]domain.RiskContextSnapshot{
			"finding-1": {
				EffectiveState:   domain.EffectiveStateSuppressed,
				RawSeverity:      "high",
				VEXAssertionID:   "assert-old",
				SuppressionReason: "old",
			},
		},
	}
	audit := &memoryAudit{}
	handler := &enrichment.Handler{Repo: repo, Audit: audit}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
	if repo.upserts[0].EffectiveState != domain.EffectiveStateDetected {
		t.Fatalf("state = %q", repo.upserts[0].EffectiveState)
	}
	if audit.entries[0].Details["trigger"] != "vex_revoked" {
		t.Fatalf("audit = %+v", audit.entries[0].Details)
	}
}

func TestReenrichVEXUsesParentSBOM(t *testing.T) {
	repo := &memoryRepo{sbomForVEX: "sbom-1"}
	handler := &enrichment.Handler{Repo: repo}
	if err := handler.ReenrichVEX(context.Background(), "vex-1"); err != nil {
		t.Fatal(err)
	}
	if repo.lastSBOM != "sbom-1" {
		t.Fatalf("sbom = %q", repo.lastSBOM)
	}
}

func TestApplyVEXFindingsListError(t *testing.T) {
	handler := &enrichment.Handler{Repo: &memoryRepo{findingsErr: errors.New("boom")}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyVEXAssertionsListError(t *testing.T) {
	handler := &enrichment.Handler{Repo: &memoryRepo{assertionsErr: errors.New("assertions failed")}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyVEXUpsertError(t *testing.T) {
	handler := &enrichment.Handler{Repo: &memoryRepo{
		findings:  []domain.EnrichmentFinding{{ComponentVulnerabilityID: "f1", RawSeverity: "high"}},
		upsertErr: errors.New("upsert failed"),
	}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestReenrichVEXLookupError(t *testing.T) {
	handler := &enrichment.Handler{Repo: &memoryRepo{sbomForVEXErr: errors.New("missing vex")}}
	if err := handler.ReenrichVEX(context.Background(), "vex-1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyVEXWithoutAuditRecorder(t *testing.T) {
	handler := &enrichment.Handler{Repo: &memoryRepo{
		findings: []domain.EnrichmentFinding{{ComponentVulnerabilityID: "f1", RawSeverity: "low"}},
		existing: map[string]domain.RiskContextSnapshot{"f1": {EffectiveState: domain.EffectiveStateDetected}},
	}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveEffectiveStateDefaults(t *testing.T) {
	state, status, reason, id := enrichment.ResolveEffectiveState(nil)
	if state != domain.EffectiveStateDetected || status != "" || reason != "" || id != "" {
		t.Fatalf("got %q %q %q %q", state, status, reason, id)
	}
}

func TestResolveEffectiveStateUnknownStatus(t *testing.T) {
	state, _, _, _ := enrichment.ResolveEffectiveState(&domain.VEXAssertionMatch{Status: "custom"})
	if state != domain.EffectiveStateDetected {
		t.Fatalf("state = %q", state)
	}
}

func TestApplyVEXGetRiskContextError(t *testing.T) {
	handler := &enrichment.Handler{Repo: &memoryRepo{
		findings: []domain.EnrichmentFinding{{ComponentVulnerabilityID: "f1", RawSeverity: "high"}},
		getErr:   errors.New("get failed"),
	}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyVEXAuditIncludesVEXDocument(t *testing.T) {
	now := time.Now()
	handler := &enrichment.Handler{Repo: &memoryRepo{
		findings: []domain.EnrichmentFinding{{
			ComponentVulnerabilityID: "finding-1",
			ComponentPURL:            "pkg:npm/a@1",
			CVEID:                    "CVE-1",
			RawSeverity:              "high",
		}},
		assertions: []domain.VEXAssertionMatch{{
			ID: "a1", VEXDocumentID: "vex-9", ComponentPURL: "pkg:npm/a@1", CVEID: "CVE-1",
			Status: domain.VEXStatusAffected, DocumentTime: now,
		}},
		existing: map[string]domain.RiskContextSnapshot{
			"finding-1": {EffectiveState: domain.EffectiveStateDetected, RawSeverity: "high"},
		},
	}, Audit: &memoryAudit{}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
}

type memoryRepo struct {
	findings     []domain.EnrichmentFinding
	assertions   []domain.VEXAssertionMatch
	existing     map[string]domain.RiskContextSnapshot
	upserts      []domain.RiskContextSnapshot
	getErr        error
	findingsErr   error
	assertionsErr error
	upsertErr     error
	sbomForVEX    string
	sbomForVEXErr error
	lastSBOM      string
}

func (m *memoryRepo) ListFindingsForSBOM(_ context.Context, sbomDocumentID string) ([]domain.EnrichmentFinding, error) {
	if m.findingsErr != nil {
		return nil, m.findingsErr
	}
	m.lastSBOM = sbomDocumentID
	return m.findings, nil
}

func (m *memoryRepo) ListAssertionsForSBOM(context.Context, string) ([]domain.VEXAssertionMatch, error) {
	if m.assertionsErr != nil {
		return nil, m.assertionsErr
	}
	return m.assertions, nil
}

func (m *memoryRepo) GetRiskContext(_ context.Context, findingID string) (domain.RiskContextSnapshot, error) {
	if m.getErr != nil {
		return domain.RiskContextSnapshot{}, m.getErr
	}
	if snapshot, ok := m.existing[findingID]; ok {
		return snapshot, nil
	}
	return domain.RiskContextSnapshot{}, nil
}

func (m *memoryRepo) UpsertRiskContext(_ context.Context, _ domain.EnrichmentFinding, snapshot domain.RiskContextSnapshot) error {
	if m.upsertErr != nil {
		return m.upsertErr
	}
	m.upserts = append(m.upserts, snapshot)
	return nil
}

func (m *memoryRepo) SBOMDocumentForVEX(_ context.Context, _ string) (string, error) {
	if m.sbomForVEXErr != nil {
		return "", m.sbomForVEXErr
	}
	return m.sbomForVEX, nil
}

func (m *memoryRepo) CountOpenRiskContexts(context.Context) (int, error) { return 0, nil }
func (m *memoryRepo) ListOpenRiskContexts(context.Context, int, int) ([]domain.OpenRiskContextRow, error) {
	return nil, nil
}
func (m *memoryRepo) UpdateRiskContextSignals(context.Context, domain.OpenRiskContextRow, *float64, bool, bool, domain.DeterministicLevel, int) error {
	return nil
}

type memoryAudit struct {
	entries []domain.AuditEntry
}

func (m *memoryAudit) Record(_ context.Context, entry domain.AuditEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}
