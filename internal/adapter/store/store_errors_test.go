package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

func TestStoreErrorPaths(t *testing.T) {
	ctx := context.Background()
	queryErr := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}
	execErr := storeFakePool{conn: storeFakeConn{execErr: errors.New("exec failed")}}

	createErrPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{errRow{err: errors.New("insert failed")}},
	}}
	if _, err := NewPostgresProductCatalogRepository(createErrPool).CreateProduct(ctx, "a", ""); err == nil {
		t.Fatal("expected create product error")
	}
	if _, err := NewPostgresProductCatalogRepository(queryErr).GetProduct(ctx, "prod-1"); err == nil {
		t.Fatal("expected get product query error")
	}

	createProjectPool := &scriptedFakePool{}
	createProjectPool.addQueryRow("prod-1", "alpha", "", time.Now().UTC())
	createProjectPool.addQueryRowErr(errors.New("insert failed"))
	if _, err := NewPostgresProductCatalogRepository(createProjectPool).CreateProject(ctx, "prod-1", "web", ""); err == nil {
		t.Fatal("expected create project error")
	}

	if _, err := NewPostgresScanQueryRepository(queryErr).GetProjectProductID(ctx, "proj-1"); err == nil {
		t.Fatal("expected get project product error")
	}

	getScanPool := &scriptedFakePool{}
	getScanPool.addQueryRow("scan-1", "proj-1", "prod-1", "sha256:abc", "cyclonedx", "verified", time.Now().UTC(), "")
	getScanPool.queryResults = append(getScanPool.queryResults, failingRows{err: errors.New("count failed")})
	if _, err := NewPostgresScanQueryRepository(getScanPool).GetScan(ctx, "scan-1"); err == nil {
		t.Fatal("expected count severities error")
	}

	if err := NewPostgresScannerConfigRepository(execErr).Save(ctx, defaultScannerSettings()); err == nil {
		t.Fatal("expected save scanner config error")
	}

	if _, err := NewPostgresEnrichmentRepository(queryErr).GetRiskContext(ctx, "art", "purl", "cve"); err == nil {
		t.Fatal("expected get risk context error")
	}
	if err := NewPostgresEnrichmentRepository(execErr).UpsertRiskContext(ctx,
		domain.EnrichmentFinding{ComponentVulnerabilityID: "cv-1", RawSeverity: "high"},
		domain.RiskContextSnapshot{EffectiveState: "open"},
	); err == nil {
		t.Fatal("expected upsert risk context error")
	}
	if _, err := NewPostgresEnrichmentRepository(queryErr).CountOpenRiskContexts(ctx); err == nil {
		t.Fatal("expected count open risk contexts error")
	}
	if err := NewPostgresEnrichmentRepository(execErr).UpdateRiskContextSignals(ctx,
		domain.OpenRiskContextRow{ArtifactID: "cv-1"}, nil, false, false, "", 0,
	); err == nil {
		t.Fatal("expected update risk context signals error")
	}
	if _, err := NewPostgresEnrichmentRepository(queryErr).ArtifactForVEX(ctx, "vex-1"); err == nil {
		t.Fatal("expected sbom document for vex error")
	}
	if _, err := NewPostgresEnrichmentRepository(storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}).ArtifactForVEX(ctx, "missing"); err == nil {
		t.Fatal("expected vex document not found")
	}

	// A component absent from the artifact's SBOMs is best-effort: the assertion is
	// still recorded with a NULL component_version_id (no error).
	missingComponent := &scriptedFakePool{}
	missingComponent.addExec(1, nil)               // delete existing assertions
	missingComponent.addQueryRow("vuln-1")         // vulnerability lookup
	missingComponent.addQueryRowErr(pgx.ErrNoRows) // component version lookup → NULL
	missingComponent.addExec(1, nil)               // insert assertion with NULL component_version_id
	if err := NewPostgresVEXAssertionWriter(missingComponent).SyncAssertions(ctx, "vex-1", "art-1", []domain.ParsedVEXAssertion{{
		CVEID: "CVE-1", ComponentPURL: "pkg:npm/missing@1",
	}}); err != nil {
		t.Fatalf("expected best-effort success, got %v", err)
	}

	if _, err := NewPostgresExploitStore(queryErr).HasPublicExploit(ctx, "CVE-1"); err == nil {
		t.Fatal("expected has public exploit error")
	}
	if _, err := NewPostgresExploitStore(queryErr).CountExploits(ctx); err == nil {
		t.Fatal("expected count exploits error")
	}

	if _, err := NewPostgresThreatSignalStore(queryErr).ListKEVCVEIDs(ctx); err == nil {
		t.Fatal("expected list kev error")
	}
	if err := NewPostgresThreatSignalStore(execErr).MarkStale(ctx, true); err == nil {
		t.Fatal("expected mark stale error")
	}
	if _, err := NewPostgresThreatSignalStore(queryErr).GetEPSSForCVE(ctx, "CVE-1"); err == nil {
		t.Fatal("expected get epss error")
	}
	if listed, err := NewPostgresThreatSignalStore(storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}).IsKEVListed(ctx, "CVE-1"); err != nil || listed {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
	if _, err := NewPostgresThreatSignalStore(queryErr).IsKEVListed(ctx, "CVE-1"); err == nil {
		t.Fatal("expected is kev listed error")
	}
	if _, err := NewPostgresThreatSignalStore(queryErr).CountEPSSRows(ctx); err == nil {
		t.Fatal("expected count epss rows error")
	}
	if _, err := NewPostgresThreatSignalStore(queryErr).LastSuccessfulFetch(ctx); err == nil {
		t.Fatal("expected last successful fetch error")
	}

	kevErrPool := &scriptedFakePool{}
	kevErrPool.queryResults = append(kevErrPool.queryResults, failingRows{err: errors.New("list kev failed")})
	if err := NewPostgresThreatSignalStore(kevErrPool).UpsertKEV(ctx, []domain.KEVSignal{{CVEID: "CVE-1"}}); err == nil {
		t.Fatal("expected upsert kev error")
	}

	if _, err := NewPostgresVEXExportRepository(queryErr).ProductExists(ctx, "prod-1"); err == nil {
		t.Fatal("expected product exists error")
	}
	if _, err := NewPostgresVEXExportRepository(queryErr).GetProductVersion(ctx, "prod-1", "1.0.0"); err == nil {
		t.Fatal("expected get product version error")
	}

	if _, err := NewPostgresTriageRepository(queryErr).GetFindingContext(ctx, "cv-1"); err == nil {
		t.Fatal("expected get finding context error")
	}
	if err := NewPostgresTriageRepository(execErr).UpdateRiskContext(ctx, domain.RiskContextTriageUpdate{}); err == nil {
		t.Fatal("expected update risk context error")
	}
	if _, err := NewPostgresTriageRepository(queryErr).LatestDecision(ctx, "cv-1"); err == nil {
		t.Fatal("expected latest decision error")
	}

	insertErrPool := &scriptedFakePool{}
	insertErrPool.addExec(0, errors.New("insert vex failed"))
	if _, err := NewPostgresTriageVEXGenerator(insertErrPool).CreateFromDecision(ctx, domain.GeneratedVEXInput{
		Issuer: "alice", DocumentTime: time.Now().UTC(),
		Finding:   domain.TriageFindingContext{FindingID: "cv-1", ArtifactID: "sbom-1", SBOMChecksum: "sum"},
		Assertion: domain.ParsedVEXAssertion{CVEID: "CVE-1", ComponentPURL: "pkg:npm/a@1", Status: "fixed"},
	}); err == nil {
		t.Fatal("expected create from decision error")
	}

	if _, err := NewPostgresWatchRepository(queryErr).HasFinding(ctx, "cvn-1", "CVE-1"); err == nil {
		t.Fatal("expected has finding error")
	}

	createWatchErr := &scriptedFakePool{}
	createWatchErr.addQueryRow(false)
	createWatchErr.addQueryRowErr(errors.New("create finding failed"))
	if _, err := NewPostgresWatchRepository(createWatchErr).CreateWatchFinding(ctx, domain.CreateWatchFindingInput{
		ComponentVersionID: "cvn-1", CVEID: "CVE-1", VulnerabilityID: "vuln-1", ArtifactID: "sbom-1",
	}); err == nil {
		t.Fatal("expected create watch finding error")
	}

	countErrPool := &scriptedFakePool{}
	countErrPool.addQueryRowErr(errors.New("count failed"))
	if _, _, _, err := NewPostgresSBOMManagementRepository(countErrPool).ListSBOMs(ctx, domain.PageRequest{}); err == nil {
		t.Fatal("expected list sboms count error")
	}

	softDeleteErr := &scriptedFakePool{}
	softDeleteErr.addQueryRow(false, nil, "sbom-1")
	softDeleteErr.addQueryRowErr(errors.New("count failed"))
	if _, err := NewPostgresSBOMManagementRepository(softDeleteErr).SoftDeleteSBOM(ctx, "sbom-1", true); err == nil {
		t.Fatal("expected soft delete count error")
	}

	createKeyErr := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{errRow{err: errors.New("create failed")}},
	}}
	if _, err := NewPostgresAPIKeyRepository(createKeyErr).Create(ctx, domain.APIKeyCreateInput{Name: "ops"}); err == nil {
		t.Fatal("expected create api key error")
	}
	if err := NewPostgresAPIKeyRepository(execErr).Revoke(ctx, "key-1"); err == nil {
		t.Fatal("expected revoke api key error")
	}
}

func TestMapSeverityToPriorityDefault(t *testing.T) {
	if mapSeverityToPriority("medium") != "medium" {
		t.Fatal("expected medium priority")
	}
}

func TestPostgresSBOMStoreSaveVEXParseError(t *testing.T) {
	store := NewPostgresSBOMStore(storeFakePool{conn: storeFakeConn{}})
	if _, err := store.SaveVEX(context.Background(), domain.SaveVEXInput{
		Format: "openvex", RawDocument: []byte("{"), ArtifactID: "sbom-1",
	}); err == nil {
		t.Fatal("expected parse vex error")
	}
}

func TestCombinedSignalReaderErrors(t *testing.T) {
	ctx := context.Background()
	reader := CombinedSignalReader{
		Threat:  stubThreatSignalStore{epssErr: errors.New("epss failed"), kevErr: errors.New("kev failed")},
		Exploit: stubExploitStore{hasErr: errors.New("exploit failed")},
	}
	if _, err := reader.GetEPSSForCVE(ctx, "CVE-1"); err == nil {
		t.Fatal("expected epss error")
	}
	if _, err := reader.IsKEVListed(ctx, "CVE-1"); err == nil {
		t.Fatal("expected kev error")
	}
	if _, err := reader.HasPublicExploit(ctx, "CVE-1"); err == nil {
		t.Fatal("expected exploit error")
	}
}

func TestThreatSignalsStaleZeroLastFetch(t *testing.T) {
	pool := &scriptedFakePool{}
	pool.addQueryRow(false)
	pool.addQueryRowErr(errors.New("last fetch failed"))
	stale, err := NewPostgresThreatSignalStore(pool).SignalsStale(context.Background())
	if err == nil || stale {
		t.Fatalf("stale=%v err=%v", stale, err)
	}
}
