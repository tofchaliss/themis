//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/domain"
)

func TestCVSSBackfillCatalogMethods(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15471)
	catalog := store.NewPostgresVulnerabilityCatalog(pool)

	// Two unknown-CVSS catalog rows.
	for _, cve := range []string{"CVE-2024-7001", "CVE-2024-7002"} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO vulnerabilities (cve_id, severity, cvss_score, ecosystem, package_name, affected_versions)
			VALUES ($1, 'unknown', 0, 'Alpine', 'openssl', ARRAY['< 3.0'])
		`, cve); err != nil {
			t.Fatal(err)
		}
	}

	before := time.Now().Add(time.Hour)
	candidates, err := catalog.ListCVEsNeedingCVSS(ctx, 10, before)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %v, want 2", candidates)
	}

	// A finding for CVE-7001 with unknown raw_severity must inherit the backfilled severity.
	productID := uuid.NewString()
	artifactID := uuid.NewString()
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), "sha256:cvss-backfill")
	if _, err := pool.Exec(ctx, `
		INSERT INTO risk_context (artifact_id, component_purl, cve_id, effective_state, priority, raw_severity)
		VALUES ($1, 'pkg:apk/openssl@1.0', 'CVE-2024-7001', 'detected', 'medium', 'unknown')
	`, artifactID); err != nil {
		t.Fatal(err)
	}

	if err := catalog.ApplyCVSS(ctx, "CVE-2024-7001", "high", 7.5, "vec"); err != nil {
		t.Fatal(err)
	}

	// Catalog row updated.
	var severity string
	var score float64
	if err := pool.QueryRow(ctx, `SELECT severity, cvss_score FROM vulnerabilities WHERE cve_id = 'CVE-2024-7001'`).Scan(&severity, &score); err != nil {
		t.Fatal(err)
	}
	if severity != "high" || score != 7.5 {
		t.Fatalf("catalog severity=%q score=%v", severity, score)
	}
	// risk_context.raw_severity propagated.
	var rawSeverity string
	if err := pool.QueryRow(ctx, `SELECT raw_severity FROM risk_context WHERE cve_id = 'CVE-2024-7001'`).Scan(&rawSeverity); err != nil {
		t.Fatal(err)
	}
	if rawSeverity != "high" {
		t.Fatalf("risk_context raw_severity = %q, want high", rawSeverity)
	}

	// CVE-7001 no longer a candidate (now scored); CVE-7002 marked checked drops out within back-off.
	if err := catalog.MarkCVSSChecked(ctx, "CVE-2024-7002"); err != nil {
		t.Fatal(err)
	}
	candidates, err = catalog.ListCVEsNeedingCVSS(ctx, 10, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates after apply+check = %v, want 0", candidates)
	}
}

// TestUpsertVulnerabilityPreservesCVSS locks in the v0.3.4 clobber fix: a feed
// re-correlation that carries no numeric CVSS (e.g. a distro OSV watch cycle) must
// NOT overwrite a real CVSS already in the catalog from the NVD-by-CVE backfill —
// otherwise the score reverts to 0/unknown and the cvss_checked_at back-off blocks
// re-filling it. A feed that DOES carry a better score still overwrites.
func TestUpsertVulnerabilityPreservesCVSS(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15481)
	catalog := store.NewPostgresVulnerabilityCatalog(pool)

	// Backfilled NVD CVSS lands first.
	if _, err := catalog.Upsert(ctx, domain.VulnerabilityRecord{
		CVEID: "CVE-2024-8001", Severity: "high", CVSSScore: 7.5, CVSSVector: "CVSS:3.1/AV:N",
		Ecosystem: "rpm", PackageName: "openssl", AffectedVersions: []string{"< 2.0"}, FixVersions: []string{"2.0"},
	}); err != nil {
		t.Fatal(err)
	}

	// Distro re-correlation with no numeric CVSS must NOT wipe it — but DOES refresh
	// the correlation metadata (fixed version).
	if _, err := catalog.Upsert(ctx, domain.VulnerabilityRecord{
		CVEID: "CVE-2024-8001", Severity: "", CVSSScore: 0, CVSSVector: "",
		Ecosystem: "rpm", PackageName: "openssl", AffectedVersions: []string{"< 3.0"},
		FixVersions: []string{"0:1.1.1k-16.el8_10"},
	}); err != nil {
		t.Fatal(err)
	}

	var severity, vector string
	var score float64
	var fixes []string
	if err := pool.QueryRow(ctx, `SELECT severity, cvss_score, cvss_vector, fix_versions
		FROM vulnerabilities WHERE cve_id = 'CVE-2024-8001'`).Scan(&severity, &score, &vector, &fixes); err != nil {
		t.Fatal(err)
	}
	if severity != "high" || score != 7.5 || vector != "CVSS:3.1/AV:N" {
		t.Fatalf("CVSS clobbered: severity=%q score=%v vector=%q", severity, score, vector)
	}
	if len(fixes) != 1 || fixes[0] != "0:1.1.1k-16.el8_10" {
		t.Fatalf("correlation metadata not refreshed: fix_versions=%v", fixes)
	}

	// A real new CVSS (e.g. an NVD re-score) DOES overwrite.
	if _, err := catalog.Upsert(ctx, domain.VulnerabilityRecord{
		CVEID: "CVE-2024-8001", Severity: "critical", CVSSScore: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L",
		Ecosystem: "rpm", PackageName: "openssl",
	}); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT severity, cvss_score FROM vulnerabilities WHERE cve_id = 'CVE-2024-8001'`).Scan(&severity, &score); err != nil {
		t.Fatal(err)
	}
	if severity != "critical" || score != 9.8 {
		t.Fatalf("real CVSS did not overwrite: severity=%q score=%v", severity, score)
	}
}
