package vexgen_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/vexgen"
)

func TestVEXPrecedence_HumanOverUpstream(t *testing.T) {
	human := domain.VEXAssertionMatch{
		ID: "human-1", CVEID: "CVE-1", ComponentPURL: "pkg:rpm/redhat/httpd@1.0",
		Status: domain.VEXStatusNotAffected, Source: domain.VEXSourceThemisGenerated,
		DocumentTime: time.Now(),
	}
	upstream := domain.VEXAssertionMatch{
		ID: "up-1", CVEID: "CVE-1", ComponentPURL: "pkg:rpm/redhat/httpd@1.0",
		Status: domain.VEXStatusAffected, Source: domain.VEXSourceUpstreamVendor,
		DocumentTime: time.Now().Add(-time.Hour),
	}
	winner := enrichment.PickWinningAssertion([]domain.VEXAssertionMatch{upstream, human})
	if winner == nil || winner.Source != domain.VEXSourceThemisGenerated {
		t.Fatalf("winner = %+v", winner)
	}
}

func TestVEXPrecedence_UserOverAI(t *testing.T) {
	manual := domain.VEXAssertionMatch{Source: domain.VEXSourceManual, DocumentTime: time.Now()}
	ai := domain.VEXAssertionMatch{Source: domain.VEXSourceAIGenerated, DocumentTime: time.Now()}
	winner := enrichment.PickWinningAssertion([]domain.VEXAssertionMatch{ai, manual})
	if winner.Source != domain.VEXSourceManual {
		t.Fatalf("winner source = %q", winner.Source)
	}
}

func TestVEXPrecedence_AIOverUpstream(t *testing.T) {
	ai := domain.VEXAssertionMatch{Source: domain.VEXSourceAIGenerated, DocumentTime: time.Now()}
	upstream := domain.VEXAssertionMatch{Source: domain.VEXSourceUpstreamVendor, DocumentTime: time.Now()}
	winner := enrichment.PickWinningAssertion([]domain.VEXAssertionMatch{upstream, ai})
	if winner.Source != domain.VEXSourceAIGenerated {
		t.Fatalf("winner source = %q", winner.Source)
	}
}

func TestVEXPrecedence_UpstreamWhenNoHuman(t *testing.T) {
	upstream := domain.VEXAssertionMatch{
		Status: domain.VEXStatusNotAffected, Source: domain.VEXSourceUpstreamVendor,
	}
	winner := enrichment.PickWinningAssertion([]domain.VEXAssertionMatch{upstream})
	if winner == nil || winner.Status != domain.VEXStatusNotAffected {
		t.Fatalf("winner = %+v", winner)
	}
}

func TestSerializeCycloneDX(t *testing.T) {
	epss := 0.42
	body, err := vexgen.SerializeCycloneDX([]domain.VEXExportEntry{{
		BOMRef: "pkg:apk/alpine/busybox@1.0", CVEID: "CVE-2024-1",
		VEXStatus: domain.VEXStatusNotAffected, Justification: "backport",
		RiskScore: 12, EPSSScore: &epss, KEVListed: true, BlastRadius: 140, Source: domain.VEXSourceThemisGenerated,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	vulns := doc["vulnerabilities"].([]any)
	vuln := vulns[0].(map[string]any)
	if vuln["x-themis-epss-score"] == nil || vuln["x-themis-kev-listed"] != true {
		t.Fatalf("extensions missing: %+v", vuln)
	}
}

func TestSerializeOpenVEX(t *testing.T) {
	body, err := vexgen.SerializeOpenVEX([]domain.VEXExportEntry{{
		BOMRef: "pkg:rpm/redhat/httpd@1.0", CVEID: "CVE-2024-2",
		VEXStatus: domain.VEXStatusAffected,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Context string `json:"@context"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Context == "" {
		t.Fatalf("doc = %+v err = %v", doc, err)
	}
}

func TestExportCoverageAggregate(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "1.0.0"},
		findings: []domain.VEXExportFinding{
			{RiskContextSnapshot: domain.RiskContextSnapshot{UpstreamVEXCoverage: domain.UpstreamVEXCoverageCovered}},
			{RiskContextSnapshot: domain.RiskContextSnapshot{UpstreamVEXCoverage: domain.UpstreamVEXCoverageNotCovered}},
			{RiskContextSnapshot: domain.RiskContextSnapshot{UpstreamVEXCoverage: domain.UpstreamVEXCoveragePURLMismatch}},
		},
	}
	svc := &vexgen.Handler{Repo: repo}
	summary, err := svc.ExportCoverage(context.Background(), "prod-1", "1.0.0")
	if err != nil || summary.Covered != 1 || summary.NotCovered != 1 || summary.PURLMismatch != 1 {
		t.Fatalf("summary = %+v err = %v", summary, err)
	}
}

func TestExportVEXPrecedenceInDocument(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "1.0.0"},
		findings: []domain.VEXExportFinding{{
			EnrichmentFinding: domain.EnrichmentFinding{
				ComponentPURL: "pkg:rpm/redhat/httpd@1.0", CVEID: "CVE-1", SBOMDocumentID: "sbom-1",
			},
			RiskContextSnapshot: domain.RiskContextSnapshot{VEXStatus: domain.VEXStatusAffected},
		}},
		assertions: map[string][]domain.VEXAssertionMatch{
			"sbom-1": {
				{ComponentPURL: "pkg:rpm/redhat/httpd@1.0", CVEID: "CVE-1", Status: domain.VEXStatusNotAffected, Source: domain.VEXSourceThemisGenerated},
				{ComponentPURL: "pkg:rpm/redhat/httpd@1.0", CVEID: "CVE-1", Status: domain.VEXStatusAffected, Source: domain.VEXSourceUpstreamVendor},
			},
		},
	}
	svc := &vexgen.Handler{Repo: repo}
	body, err := svc.ExportVEX(context.Background(), "prod-1", "1.0.0", domain.VEXExportFormatCycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vulnerabilities []struct {
			Analysis struct {
				State string `json:"state"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].Analysis.State != "not_affected" {
		t.Fatalf("export = %s", string(body))
	}
}

func TestExportProductNotFound(t *testing.T) {
	svc := &vexgen.Handler{Repo: &memoryExportRepo{productExists: false}}
	_, err := svc.ExportVEX(context.Background(), "missing", "1.0.0", domain.VEXExportFormatCycloneDX)
	if !errors.Is(err, domain.ErrProductNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestExportVEXWithVendorMatch(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "3.0.0"},
		findings: []domain.VEXExportFinding{{
			EnrichmentFinding: domain.EnrichmentFinding{
				ComponentPURL: "pkg:rpm/redhat/httpd@1.0", CVEID: "CVE-V", SBOMDocumentID: "sbom-v",
			},
		}},
	}
	svc := &vexgen.Handler{
		Repo:        repo,
		VendorVEX:   stubVendorReader{},
		VendorMatch: stubVendorMatcher{},
	}
	body, err := svc.ExportVEX(context.Background(), "prod-1", "3.0.0", domain.VEXExportFormatCycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "not_affected") {
		t.Fatalf("body=%s", body)
	}
}

func TestExportCoverageVersionNotFound(t *testing.T) {
	repo := &memoryExportRepo{version: domain.ProductVersion{ProductID: "prod-1", Version: "1.0.0"}}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportCoverage(context.Background(), "prod-1", "9.9.9")
	if !errors.Is(err, domain.ErrProductVersionNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestEntryFromFindingWithoutWinner(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "4.0.0"},
		findings: []domain.VEXExportFinding{{
			EnrichmentFinding: domain.EnrichmentFinding{ComponentPURL: "pkg:generic/a@1", CVEID: "CVE-X", SBOMDocumentID: "sbom-x"},
			RiskContextSnapshot: domain.RiskContextSnapshot{VEXStatus: domain.VEXStatusAffected, RiskScore: 5},
		}},
	}
	svc := &vexgen.Handler{Repo: repo}
	body, err := svc.ExportVEX(context.Background(), "prod-1", "4.0.0", domain.VEXExportFormatCycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "affected") {
		t.Fatalf("body=%s", body)
	}
}

type stubVendorReader struct{}

func (stubVendorReader) ListVendorAssertionsForCVE(context.Context, string) ([]domain.VendorVEXAssertion, error) {
	return []domain.VendorVEXAssertion{{CVEID: "CVE-V", Status: domain.VEXStatusNotAffected}}, nil
}

type stubVendorMatcher struct{}

func (stubVendorMatcher) Match(string, string, []domain.VendorVEXAssertion) enrichment.VendorMatchResult {
	return enrichment.VendorMatchResult{
		Matched: true, Status: domain.VEXStatusNotAffected,
		Assertion: domain.VendorVEXAssertion{Justification: "vendor"},
	}
}

func TestExportCoverageRepoError(t *testing.T) {
	repo := &memoryExportRepo{
		version:      domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "1.0.0"},
		findingsErr:  errors.New("db down"),
	}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportCoverage(context.Background(), "prod-1", "1.0.0")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildEntriesListFindingsError(t *testing.T) {
	repo := &memoryExportRepo{
		version:     domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "1.0.0"},
		findingsErr: errors.New("list failed"),
	}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportVEX(context.Background(), "prod-1", "1.0.0", domain.VEXExportFormatCycloneDX)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnsureProductExistsError(t *testing.T) {
	repo := &memoryExportRepo{existsErr: errors.New("exists failed")}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportVEX(context.Background(), "prod-1", "1.0.0", domain.VEXExportFormatCycloneDX)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVendorAssertionMatchFallbackStatus(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "5.0.0"},
		findings: []domain.VEXExportFinding{{
			EnrichmentFinding: domain.EnrichmentFinding{
				ComponentPURL: "pkg:rpm/redhat/httpd@1.0", CVEID: "CVE-V2", SBOMDocumentID: "sbom-v2",
			},
		}},
	}
	svc := &vexgen.Handler{
		Repo:        repo,
		VendorVEX:   stubVendorReader{},
		VendorMatch: stubVendorMatcherEmptyStatus{},
	}
	if _, err := svc.ExportVEX(context.Background(), "prod-1", "5.0.0", domain.VEXExportFormatCycloneDX); err != nil {
		t.Fatal(err)
	}
}

type stubVendorMatcherEmptyStatus struct{}

func (stubVendorMatcherEmptyStatus) Match(string, string, []domain.VendorVEXAssertion) enrichment.VendorMatchResult {
	return enrichment.VendorMatchResult{
		Matched:   true,
		Assertion: domain.VendorVEXAssertion{Status: domain.VEXStatusAffected, Justification: "from assertion"},
	}
}

func TestParseExportFormat(t *testing.T) {
	if vexgen.ParseExportFormat("openvex") != domain.VEXExportFormatOpenVEX {
		t.Fatal("expected openvex")
	}
	if vexgen.FormatFromAccept("application/openvex+json") != domain.VEXExportFormatOpenVEX {
		t.Fatal("expected accept openvex")
	}
	if vexgen.FormatFromAccept("application/json") != domain.VEXExportFormatCycloneDX {
		t.Fatal("expected default accept")
	}
	if vexgen.ParseExportFormat("") != domain.VEXExportFormatCycloneDX {
		t.Fatal("expected default cyclonedx")
	}
}

func TestExportVEXOpenVEXFormat(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "2.0.0"},
	}
	svc := &vexgen.Handler{Repo: repo}
	body, err := svc.ExportVEX(context.Background(), "prod-1", "2.0.0", domain.VEXExportFormatOpenVEX)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("expected body")
	}
}

func TestMapCycloneDXStates(t *testing.T) {
	body, err := vexgen.SerializeCycloneDX([]domain.VEXExportEntry{
		{BOMRef: "p", CVEID: "CVE-1", VEXStatus: domain.VEXStatusFixed},
		{BOMRef: "p2", CVEID: "CVE-2", VEXStatus: domain.VEXStatusUnderInvestigation},
		{BOMRef: "p3", CVEID: "CVE-3", VEXStatus: "unknown"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(body), "resolved", "in_triage") {
		t.Fatalf("body=%s", body)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

type memoryExportRepo struct {
	productExists bool
	version       domain.ProductVersion
	findings      []domain.VEXExportFinding
	assertions    map[string][]domain.VEXAssertionMatch
	findingsErr   error
	existsErr     error
	assertionsErr error
}

type flakyVersionRepo struct {
	*memoryExportRepo
	getVersionCalls     int
	versionFailOnSecond bool
}

func (f *flakyVersionRepo) GetProductVersion(ctx context.Context, productID, version string) (domain.ProductVersion, error) {
	f.getVersionCalls++
	if f.getVersionCalls > 1 && f.versionFailOnSecond {
		return domain.ProductVersion{}, errors.New("second lookup failed")
	}
	return f.memoryExportRepo.GetProductVersion(ctx, productID, version)
}

func (m *memoryExportRepo) ProductExists(context.Context, string) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	if m.productExists {
		return true, nil
	}
	return m.version.ProductID != "", nil
}

func (m *memoryExportRepo) GetProductVersion(_ context.Context, productID, version string) (domain.ProductVersion, error) {
	if m.version.ProductID == "" || m.version.Version != version {
		return domain.ProductVersion{}, domain.ErrProductVersionNotFound
	}
	return m.version, nil
}

func (m *memoryExportRepo) ListFindingsForProductVersion(context.Context, string) ([]domain.VEXExportFinding, error) {
	if m.findingsErr != nil {
		return nil, m.findingsErr
	}
	return m.findings, nil
}

func (m *memoryExportRepo) ListAssertionsForSBOM(_ context.Context, sbomID string) ([]domain.VEXAssertionMatch, error) {
	if m.assertionsErr != nil {
		return nil, m.assertionsErr
	}
	if m.assertions == nil {
		return nil, nil
	}
	return m.assertions[sbomID], nil
}

type errVendorReader struct{ err error }

func (e errVendorReader) ListVendorAssertionsForCVE(context.Context, string) ([]domain.VendorVEXAssertion, error) {
	return nil, e.err
}

func TestExportCoverageProductNotFound(t *testing.T) {
	repo := &memoryExportRepo{productExists: false, version: domain.ProductVersion{}}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportCoverage(context.Background(), "missing", "1.0.0")
	if !errors.Is(err, domain.ErrProductNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestExportCoverageExistsError(t *testing.T) {
	repo := &memoryExportRepo{existsErr: errors.New("exists query failed")}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportCoverage(context.Background(), "prod-1", "1.0.0")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEntryFromFindingResolveJustification(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "9.0.0"},
		findings: []domain.VEXExportFinding{{
			EnrichmentFinding: domain.EnrichmentFinding{ComponentPURL: "pkg:a/b@1", CVEID: "CVE-9", SBOMDocumentID: "sbom-9"},
		}},
		assertions: map[string][]domain.VEXAssertionMatch{
			"sbom-9": {{
				ComponentPURL: "pkg:a/b@1", CVEID: "CVE-9", Status: domain.VEXStatusNotAffected,
				Source: domain.VEXSourceThemisGenerated, VEXDocumentID: "vex-9",
			}},
		},
	}
	svc := &vexgen.Handler{Repo: repo}
	body, err := svc.ExportVEX(context.Background(), "prod-1", "9.0.0", domain.VEXExportFormatCycloneDX)
	if err != nil || !strings.Contains(string(body), "VEX doc vex-9") {
		t.Fatalf("err=%v body=%s", err, body)
	}
}

func TestExportCoverageListError(t *testing.T) {
	repo := &memoryExportRepo{
		version:     domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "1.0.0"},
		findingsErr: errors.New("list findings failed"),
	}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportCoverage(context.Background(), "prod-1", "1.0.0")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEntryFromFindingDefaultStatus(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "10.0.0"},
		findings: []domain.VEXExportFinding{{
			EnrichmentFinding: domain.EnrichmentFinding{ComponentPURL: "pkg:a/b@1", CVEID: "CVE-10", SBOMDocumentID: "sbom-10"},
			RiskContextSnapshot: domain.RiskContextSnapshot{},
		}},
	}
	svc := &vexgen.Handler{Repo: repo}
	body, err := svc.ExportVEX(context.Background(), "prod-1", "10.0.0", domain.VEXExportFormatOpenVEX)
	if err != nil || !strings.Contains(string(body), domain.VEXStatusUnderInvestigation) {
		t.Fatalf("err=%v body=%s", err, body)
	}
}

func TestBuildEntriesCacheHits(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "11.0.0"},
		findings: []domain.VEXExportFinding{
			{EnrichmentFinding: domain.EnrichmentFinding{ComponentPURL: "pkg:a/a@1", CVEID: "CVE-A", SBOMDocumentID: "sbom-shared"}},
			{EnrichmentFinding: domain.EnrichmentFinding{ComponentPURL: "pkg:a/b@1", CVEID: "CVE-B", SBOMDocumentID: "sbom-shared"}},
		},
		assertions: map[string][]domain.VEXAssertionMatch{
			"sbom-shared": {
				{ComponentPURL: "pkg:a/a@1", CVEID: "CVE-A", Status: domain.VEXStatusAffected},
				{ComponentPURL: "pkg:a/b@1", CVEID: "CVE-B", Status: domain.VEXStatusAffected},
			},
		},
	}
	svc := &vexgen.Handler{Repo: repo, VendorVEX: stubVendorReader{}, VendorMatch: stubVendorMatcherNoMatch{}}
	if _, err := svc.ExportVEX(context.Background(), "prod-1", "11.0.0", domain.VEXExportFormatCycloneDX); err != nil {
		t.Fatal(err)
	}
}

type stubVendorMatcherNoMatch struct{}

func (stubVendorMatcherNoMatch) Match(string, string, []domain.VendorVEXAssertion) enrichment.VendorMatchResult {
	return enrichment.VendorMatchResult{Matched: false}
}

func TestExportCoverageSecondVersionLookupError(t *testing.T) {
	base := &memoryExportRepo{version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "1.0.0"}}
	repo := &flakyVersionRepo{memoryExportRepo: base, versionFailOnSecond: true}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportCoverage(context.Background(), "prod-1", "1.0.0")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExportVEXSecondVersionLookupError(t *testing.T) {
	base := &memoryExportRepo{version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "1.0.0"}}
	repo := &flakyVersionRepo{memoryExportRepo: base, versionFailOnSecond: true}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportVEX(context.Background(), "prod-1", "1.0.0", domain.VEXExportFormatCycloneDX)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildEntriesAssertionsError(t *testing.T) {
	repo := &memoryExportRepo{
		version:       domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "6.0.0"},
		findings:      []domain.VEXExportFinding{{EnrichmentFinding: domain.EnrichmentFinding{SBOMDocumentID: "sbom-e"}}},
		assertionsErr: errors.New("assertions failed"),
	}
	svc := &vexgen.Handler{Repo: repo}
	_, err := svc.ExportVEX(context.Background(), "prod-1", "6.0.0", domain.VEXExportFormatCycloneDX)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildEntriesVendorError(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "7.0.0"},
		findings: []domain.VEXExportFinding{{
			EnrichmentFinding: domain.EnrichmentFinding{CVEID: "CVE-E", SBOMDocumentID: "sbom-e2"},
		}},
	}
	svc := &vexgen.Handler{Repo: repo, VendorVEX: errVendorReader{err: errors.New("vendor failed")}, VendorMatch: stubVendorMatcher{}}
	_, err := svc.ExportVEX(context.Background(), "prod-1", "7.0.0", domain.VEXExportFormatCycloneDX)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEntryFromFindingUsesResolveEffectiveState(t *testing.T) {
	repo := &memoryExportRepo{
		version: domain.ProductVersion{ID: "pv-1", ProductID: "prod-1", Version: "8.0.0"},
		findings: []domain.VEXExportFinding{{
			EnrichmentFinding: domain.EnrichmentFinding{ComponentPURL: "pkg:a/b@1", CVEID: "CVE-8", SBOMDocumentID: "sbom-8"},
		}},
		assertions: map[string][]domain.VEXAssertionMatch{
			"sbom-8": {{
				ComponentPURL: "pkg:a/b@1", CVEID: "CVE-8", Status: domain.VEXStatusNotAffected,
				Source: domain.VEXSourceThemisGenerated,
			}},
		},
	}
	svc := &vexgen.Handler{Repo: repo}
	body, err := svc.ExportVEX(context.Background(), "prod-1", "8.0.0", domain.VEXExportFormatCycloneDX)
	if err != nil || !strings.Contains(string(body), "not_affected") {
		t.Fatalf("err=%v body=%s", err, body)
	}
}
