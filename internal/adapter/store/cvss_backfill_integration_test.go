//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/adapter/store"
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
