//go:build integration

package store_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

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
	imageID := uuid.NewString()
	sbomID := uuid.NewString()
	vulnID := uuid.NewString()
	findingID := uuid.NewString()
	componentID := uuid.NewString()
	cveID := "CVE-2024-ALPINE-17"

	seedBaseData(t, ctx, pool, productID, uuid.NewString(), imageID, "sha256:ac17-alpine")
	if _, err := pool.Exec(ctx, `
		INSERT INTO sbom_documents (id, image_id, image_digest, checksum_sha256, format, spec_version, raw_document, trust_status, is_latest)
		VALUES ($1, $2, 'sha256:ac17-alpine', 'checksum-ac17', 'cyclonedx', '1.6', '{}', 'unsigned', true)
	`, sbomID, imageID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO components (id, purl, name, ecosystem) VALUES ($1, 'pkg:apk/alpine/busybox@1.35.0-r6', 'busybox', 'apk')
	`, componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_versions (id, component_id, version, sbom_document_id)
		VALUES ($1, $2, '1.35.0-r6', $3)
	`, uuid.NewString(), componentID, sbomID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (id, cve_id, severity) VALUES ($1, $2, 'medium')
	`, vulnID, cveID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_vulnerabilities (id, component_version_id, vulnerability_id, sbom_document_id)
		VALUES ($1, (SELECT id FROM component_versions WHERE sbom_document_id = $2 LIMIT 1), $3, $2)
	`, findingID, sbomID, vulnID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO risk_context (id, component_vulnerability_id, effective_state, priority, risk_score, raw_severity)
		VALUES ($1, $2, 'detected', 'medium', 40, 'medium')
	`, uuid.NewString(), findingID); err != nil {
		t.Fatal(err)
	}

	if _, err := vendorStore.UpsertAssertions(ctx, "alpine", []domain.VendorVEXAssertion{{
		AdvisoryID: "ALPINE-AC17", CVEID: cveID, Ecosystem: "Alpine", PackageName: "busybox",
		Introduced: "0", Fixed: "1.35.0-r6", Status: domain.VEXStatusNotAffected,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := handler.ApplyVEX(ctx, sbomID); err != nil {
		t.Fatal(err)
	}

	var state, coverage string
	if err := pool.QueryRow(ctx, `
		SELECT effective_state, COALESCE(upstream_vex_coverage, '')
		FROM risk_context WHERE component_vulnerability_id = $1
	`, findingID).Scan(&state, &coverage); err != nil {
		t.Fatal(err)
	}
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
	imageID := uuid.NewString()
	sbomID := uuid.NewString()
	vulnID := uuid.NewString()
	findingID := uuid.NewString()
	componentID := uuid.NewString()
	cveID := "CVE-2023-25690"

	seedBaseData(t, ctx, pool, productID, uuid.NewString(), imageID, "sha256:ac18-rhel")
	if _, err := pool.Exec(ctx, `
		INSERT INTO sbom_documents (id, image_id, image_digest, checksum_sha256, format, spec_version, raw_document, trust_status, is_latest)
		VALUES ($1, $2, 'sha256:ac18-rhel', 'checksum-ac18', 'cyclonedx', '1.6', '{}', 'unsigned', true)
	`, sbomID, imageID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO components (id, purl, name, ecosystem)
		VALUES ($1, 'pkg:rpm/rhel/httpd@2.4.37-51.el8', 'httpd', 'rpm')
	`, componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_versions (id, component_id, version, sbom_document_id)
		VALUES ($1, $2, '2.4.37-51.el8', $3)
	`, uuid.NewString(), componentID, sbomID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerabilities (id, cve_id, severity) VALUES ($1, $2, 'high')`, vulnID, cveID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_vulnerabilities (id, component_version_id, vulnerability_id, sbom_document_id)
		VALUES ($1, (SELECT id FROM component_versions WHERE sbom_document_id = $2 LIMIT 1), $3, $2)
	`, findingID, sbomID, vulnID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO risk_context (id, component_vulnerability_id, effective_state, priority, risk_score, raw_severity)
		VALUES ($1, $2, 'detected', 'high', 70, 'high')
	`, uuid.NewString(), findingID); err != nil {
		t.Fatal(err)
	}

	if _, err := vendorStore.UpsertAssertions(ctx, "rhel", []domain.VendorVEXAssertion{{
		AdvisoryID: "RHSA-AC18", CVEID: cveID,
		ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8",
		Status:      domain.VEXStatusNotAffected,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := handler.ApplyVEX(ctx, sbomID); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT effective_state FROM risk_context WHERE component_vulnerability_id = $1`, findingID).Scan(&state); err != nil {
		t.Fatal(err)
	}
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
	imageID := uuid.NewString()
	sbomID := uuid.NewString()
	seedBaseData(t, ctx, pool, productID, uuid.NewString(), imageID, "sha256:coverage-states")

	insertFinding := func(id, purl, cve, vulnID string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO sbom_documents (id, image_id, image_digest, checksum_sha256, format, spec_version, raw_document, trust_status, is_latest)
			VALUES ($1, $2, $3, $4, 'cyclonedx', '1.6', '{}', 'unsigned', true)
			ON CONFLICT DO NOTHING
		`, sbomID, imageID, "sha256:coverage-states", "checksum-cov"); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO components (id, purl, name, ecosystem) VALUES ($1, $2, 'c', 'rpm')`, uuid.NewString(), purl); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO component_versions (id, component_id, version, sbom_document_id)
			SELECT gen_random_uuid(), c.id, '1.0', $2 FROM components c WHERE c.purl = $1
		`, purl, sbomID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO vulnerabilities (id, cve_id, severity) VALUES ($1, $2, 'low') ON CONFLICT DO NOTHING`, vulnID, cve); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO component_vulnerabilities (id, component_version_id, vulnerability_id, sbom_document_id)
			VALUES ($1, (SELECT cvn.id FROM component_versions cvn JOIN components c ON c.id = cvn.component_id WHERE c.purl = $2 AND cvn.sbom_document_id = $3 LIMIT 1),
			        $4, $3)
		`, id, purl, sbomID, vulnID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO risk_context (id, component_vulnerability_id, effective_state, priority, risk_score, raw_severity)
			VALUES ($1, $2, 'detected', 'low', 10, 'low')
		`, uuid.NewString(), id); err != nil {
			t.Fatal(err)
		}
	}

	coveredID := uuid.NewString()
	mismatchID := uuid.NewString()
	noneID := uuid.NewString()
	insertFinding(coveredID, "pkg:rpm/rhel/httpd@2.4.37-51.el8", "CVE-COVERED", uuid.NewString())
	insertFinding(mismatchID, "pkg:rpm/rhel/wrong@1.0.0", "CVE-MISMATCH", uuid.NewString())
	insertFinding(noneID, "pkg:rpm/rhel/novex@1.0.0", "CVE-NOCVE", uuid.NewString())

	if _, err := vendorStore.UpsertAssertions(ctx, "rhel", []domain.VendorVEXAssertion{
		{AdvisoryID: "RHSA-C", CVEID: "CVE-COVERED", ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8", Status: domain.VEXStatusNotAffected},
		{AdvisoryID: "RHSA-M", CVEID: "CVE-MISMATCH", ComponentPURL: "pkg:rpm/redhat/other@9.9.9", Status: domain.VEXStatusNotAffected},
	}); err != nil {
		t.Fatal(err)
	}
	if err := handler.ApplyVEX(ctx, sbomID); err != nil {
		t.Fatal(err)
	}

	var covered, mismatch, none string
	_ = pool.QueryRow(ctx, `SELECT COALESCE(upstream_vex_coverage,'') FROM risk_context WHERE component_vulnerability_id = $1`, coveredID).Scan(&covered)
	_ = pool.QueryRow(ctx, `SELECT COALESCE(upstream_vex_coverage,'') FROM risk_context WHERE component_vulnerability_id = $1`, mismatchID).Scan(&mismatch)
	_ = pool.QueryRow(ctx, `SELECT COALESCE(upstream_vex_coverage,'') FROM risk_context WHERE component_vulnerability_id = $1`, noneID).Scan(&none)
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
