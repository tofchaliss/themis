package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

func TestPostgresEnrichmentRepository(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	epss := 0.42
	level := "High"

	findingsRows := &fakeRows{data: [][]any{
		{"cv-1", "pkg:npm/a@1", "CVE-1", "high", 7.5, "vuln-1", "prod-1", "scan-1", "art-1", "comp-1"},
	}}
	findingsPool := storeFakePool{conn: storeFakeConn{}, rows: findingsRows}
	findings, err := NewPostgresEnrichmentRepository(findingsPool).ListFindingsForArtifact(ctx, "art-1")
	if err != nil || len(findings) != 1 || findings[0].CVEID != "CVE-1" {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}

	assertionRows := &fakeRows{data: [][]any{
		{"va-1", "vex-1", "pkg:npm/a@1", "CVE-1", "not_affected", "fixed", now, "manual"},
	}}
	assertionPool := storeFakePool{conn: storeFakeConn{}, rows: assertionRows}
	assertions, err := NewPostgresEnrichmentRepository(assertionPool).ListAssertionsForArtifact(ctx, "sbom-1")
	if err != nil || len(assertions) != 1 || assertions[0].Status != "not_affected" {
		t.Fatalf("assertions=%+v err=%v", assertions, err)
	}

	riskPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{
			"open", "high", "not_affected", "va-1", "justified",
			float64(70), epss, true, true, level, 1.5,
		}}},
	}}
	snapshot, err := NewPostgresEnrichmentRepository(riskPool).GetRiskContext(ctx, "art-1", "pkg:npm/a@1", "CVE-1")
	if err != nil || snapshot.RiskScore != 70 || snapshot.DeterministicLevel != domain.DeterministicLevelHigh {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}

	emptyRiskPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	emptySnapshot, err := NewPostgresEnrichmentRepository(emptyRiskPool).GetRiskContext(ctx, "art-x", "pkg:x", "CVE-x")
	if err != nil || emptySnapshot.EffectiveState != "" {
		t.Fatalf("snapshot=%+v err=%v", emptySnapshot, err)
	}

	upsertPool := storeFakePool{conn: storeFakeConn{}}
	err = NewPostgresEnrichmentRepository(upsertPool).UpsertRiskContext(ctx,
		domain.EnrichmentFinding{ArtifactID: "art-1", ComponentPURL: "pkg:npm/a@1", CVEID: "CVE-1", RawSeverity: "high"},
		domain.RiskContextSnapshot{
			EffectiveState: "open", RawSeverity: "high", RiskScore: 70,
			VEXStatus: "not_affected", VEXAssertionID: "va-1",
			DeterministicLevel: domain.DeterministicLevelHigh, BlastRadiusScore: 1.2,
			UpstreamVEXCoverage: domain.UpstreamVEXCoverageCovered,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	countPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{12}}},
	}}
	count, err := NewPostgresEnrichmentRepository(countPool).CountOpenRiskContexts(ctx)
	if err != nil || count != 12 {
		t.Fatalf("count=%d err=%v", count, err)
	}

	openRows := &fakeRows{data: [][]any{
		{"art-1", "pkg:npm/a@1", "CVE-1", "high", "detected", 7.5, 1.2},
	}}
	openPool := storeFakePool{conn: storeFakeConn{}, rows: openRows}
	openRowsOut, err := NewPostgresEnrichmentRepository(openPool).ListOpenRiskContexts(ctx, 0, 0)
	if err != nil || len(openRowsOut) != 1 {
		t.Fatalf("open=%+v err=%v", openRowsOut, err)
	}

	updatePool := storeFakePool{conn: storeFakeConn{}}
	score := 0.5
	err = NewPostgresEnrichmentRepository(updatePool).UpdateRiskContextSignals(ctx,
		domain.OpenRiskContextRow{ArtifactID: "art-1", ComponentPURL: "pkg:npm/a@1", CVEID: "CVE-1"},
		&score, true, false, domain.DeterministicLevelCritical, 90,
	)
	if err != nil {
		t.Fatal(err)
	}

	vexPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"sbom-1"}}},
	}}
	sbomID, err := NewPostgresEnrichmentRepository(vexPool).ArtifactForVEX(ctx, "vex-1")
	if err != nil || sbomID != "sbom-1" {
		t.Fatalf("sbomID=%q err=%v", sbomID, err)
	}

	queryErr := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}
	if _, err := NewPostgresEnrichmentRepository(queryErr).ListFindingsForArtifact(ctx, "sbom-1"); err == nil {
		t.Fatal("expected list findings error")
	}
}

func TestPostgresVEXAssertionWriterSyncAssertions(t *testing.T) {
	ctx := context.Background()
	pool := &scriptedFakePool{}
	pool.addExec(1, nil) // delete
	pool.addQueryRow("vuln-1")
	pool.addQueryRow("cvn-1")
	pool.addExec(1, nil) // insert

	writer := NewPostgresVEXAssertionWriter(pool)
	err := writer.SyncAssertions(ctx, "vex-1", "sbom-1", []domain.ParsedVEXAssertion{{
		CVEID: "CVE-1", ComponentPURL: "pkg:npm/a@1", Status: "not_affected",
	}})
	if err != nil {
		t.Fatal(err)
	}

	missingVuln := &scriptedFakePool{}
	missingVuln.addExec(1, nil)
	missingVuln.addQueryRowErr(pgx.ErrNoRows)
	if err := NewPostgresVEXAssertionWriter(missingVuln).SyncAssertions(ctx, "vex-1", "sbom-1", []domain.ParsedVEXAssertion{{
		CVEID: "CVE-404",
	}}); err == nil {
		t.Fatal("expected vulnerability lookup error")
	}
}

func TestNullIfEmpty(t *testing.T) {
	if nullIfEmpty("") != nil {
		t.Fatal("expected nil for empty string")
	}
	if nullIfEmpty("value") != "value" {
		t.Fatal("expected value")
	}
}

func TestParseVEXAssertionsFormats(t *testing.T) {
	raw := []byte(`{"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"fixed"}]}`)
	for _, format := range []string{"openvex", "cyclonedx", "csaf", "unknown"} {
		assertions, err := parseVEXAssertions(format, raw)
		if err != nil || len(assertions) != 1 {
			t.Fatalf("format=%s assertions=%+v err=%v", format, assertions, err)
		}
	}
}

func TestPostgresSBOMStoreSaveVEXWithAssertions(t *testing.T) {
	ctx := context.Background()
	raw := []byte(`{"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"not_affected"}]}`)
	pool := &scriptedFakePool{}
	pool.addExec(1, nil) // insert vex
	pool.addExec(1, nil) // delete assertions
	pool.addQueryRow("vuln-1")
	pool.addQueryRow("cvn-1")
	pool.addExec(1, nil) // insert assertion

	store := &PostgresSBOMStore{pool: pool}
	id, err := store.SaveVEX(ctx, domain.SaveVEXInput{
		Format: "openvex", RawDocument: raw, ArtifactID: "art-1",
		TrustResult: domain.TrustResult{Status: domain.TrustStatusVerified},
	})
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}
