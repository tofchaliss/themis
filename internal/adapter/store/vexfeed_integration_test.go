//go:build integration

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// vexCoverageQuery returns the effective_state + upstream_vex_coverage for a finding identity.
func riskStateCoverage(t *testing.T, ctx context.Context, pool *pgxpool.Pool, artifactID, purl, cveID string) (state, coverage string) {
	t.Helper()
	if err := pool.QueryRow(ctx, `
		SELECT effective_state, COALESCE(upstream_vex_coverage, '')
		FROM risk_context WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, artifactID, purl, cveID).Scan(&state, &coverage); err != nil {
		t.Fatal(err)
	}
	return state, coverage
}

func TestAC17_AlpineVendorVEXNotAffected(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15470)
	vendorStore := vexfeed.NewPostgresAssertionStore(pool)
	enrichmentRepo := store.NewPostgresEnrichmentRepository(pool)
	matcher := vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{}}
	handler := &enrichment.Handler{
		Repo:        enrichmentRepo,
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vendorStore},
		VendorMatch: matcher,
	}

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	cveID := "CVE-2024-ALPINE-17"

	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), "sha256:ac17-alpine")
	_, purl := seedFinding(t, ctx, pool, artifactID, "pkg:apk/alpine/busybox", "1.35.0-r6", cveID, "medium", "")

	if _, err := vendorStore.UpsertAssertions(ctx, "alpine", []domain.VendorVEXAssertion{{
		AdvisoryID: "ALPINE-AC17", CVEID: cveID, Ecosystem: "Alpine", PackageName: "busybox",
		Introduced: "0", Fixed: "1.35.0-r6", Status: domain.VEXStatusNotAffected,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := handler.ApplyVEX(ctx, artifactID); err != nil {
		t.Fatal(err)
	}

	state, coverage := riskStateCoverage(t, ctx, pool, artifactID, purl, cveID)
	if state != domain.EffectiveStateNotAffected {
		t.Fatalf("state = %q, want not_affected", state)
	}
	if coverage != string(domain.UpstreamVEXCoverageCovered) {
		t.Fatalf("coverage = %q, want covered", coverage)
	}
}

func TestAC18_RPMNamespaceAlias(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15471)
	vendorStore := vexfeed.NewPostgresAssertionStore(pool)
	enrichmentRepo := store.NewPostgresEnrichmentRepository(pool)
	handler := &enrichment.Handler{
		Repo:        enrichmentRepo,
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vendorStore},
		VendorMatch: vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{}},
	}

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	cveID := "CVE-2023-25690"

	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), "sha256:ac18-rhel")
	_, purl := seedFinding(t, ctx, pool, artifactID, "pkg:rpm/rhel/httpd", "2.4.37-51.el8", cveID, "high", "")

	if _, err := vendorStore.UpsertAssertions(ctx, "rhel", []domain.VendorVEXAssertion{{
		AdvisoryID: "RHSA-AC18", CVEID: cveID,
		ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8",
		Status:        domain.VEXStatusNotAffected,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := handler.ApplyVEX(ctx, artifactID); err != nil {
		t.Fatal(err)
	}
	state, _ := riskStateCoverage(t, ctx, pool, artifactID, purl, cveID)
	if state != domain.EffectiveStateNotAffected {
		t.Fatalf("state = %q", state)
	}
}

func TestAC19_HttpdBackportAuthority(t *testing.T) {
	TestAC18_RPMNamespaceAlias(t)
}

func TestUpstreamVEXCoverageStates(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15472)
	vendorStore := vexfeed.NewPostgresAssertionStore(pool)
	enrichmentRepo := store.NewPostgresEnrichmentRepository(pool)
	handler := &enrichment.Handler{
		Repo:        enrichmentRepo,
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vendorStore},
		VendorMatch: vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{Logger: &vexfeed.CaptureMismatchLogger{}}},
	}

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), "sha256:coverage-states")

	// All three findings share one scan so they are all "current" (latest-scan).
	sbomID, scanReportID := seedScan(t, ctx, pool, artifactID)
	coveredPURL := addFinding(t, ctx, pool, artifactID, sbomID, scanReportID, "pkg:rpm/rhel/httpd", "2.4.37-51.el8", "CVE-COVERED", "low", "")
	mismatchPURL := addFinding(t, ctx, pool, artifactID, sbomID, scanReportID, "pkg:rpm/rhel/wrong", "1.0.0", "CVE-MISMATCH", "low", "")
	nonePURL := addFinding(t, ctx, pool, artifactID, sbomID, scanReportID, "pkg:rpm/rhel/novex", "1.0.0", "CVE-NOCVE", "low", "")

	if _, err := vendorStore.UpsertAssertions(ctx, "rhel", []domain.VendorVEXAssertion{
		{AdvisoryID: "RHSA-C", CVEID: "CVE-COVERED", ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8", Status: domain.VEXStatusNotAffected},
		{AdvisoryID: "RHSA-M", CVEID: "CVE-MISMATCH", ComponentPURL: "pkg:rpm/redhat/other@9.9.9", Status: domain.VEXStatusNotAffected},
	}); err != nil {
		t.Fatal(err)
	}
	if err := handler.ApplyVEX(ctx, artifactID); err != nil {
		t.Fatal(err)
	}

	_, covered := riskStateCoverage(t, ctx, pool, artifactID, coveredPURL, "CVE-COVERED")
	_, mismatch := riskStateCoverage(t, ctx, pool, artifactID, mismatchPURL, "CVE-MISMATCH")
	_, none := riskStateCoverage(t, ctx, pool, artifactID, nonePURL, "CVE-NOCVE")
	if covered != string(domain.UpstreamVEXCoverageCovered) {
		t.Fatalf("covered = %q", covered)
	}
	if mismatch != string(domain.UpstreamVEXCoveragePURLMismatch) {
		t.Fatalf("mismatch = %q", mismatch)
	}
	if none != string(domain.UpstreamVEXCoverageNotCovered) {
		t.Fatalf("not_covered = %q", none)
	}
}
