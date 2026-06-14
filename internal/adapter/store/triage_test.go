package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

func TestPostgresTriageRepository(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	scopePool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"prod-1"}}},
	}}
	productID, err := NewPostgresTriageRepository(scopePool).GetFindingScope(ctx, "cv-1")
	if err != nil || productID != "prod-1" {
		t.Fatalf("productID=%q err=%v", productID, err)
	}

	contextPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{
			"cv-1", "pkg:npm/a@1", "CVE-1", "sbom-1", "checksum", "high", "detected",
		}}},
	}}
	finding, err := NewPostgresTriageRepository(contextPool).GetFindingContext(ctx, "cv-1")
	if err != nil || finding.CVEID != "CVE-1" || finding.EffectiveState != "detected" {
		t.Fatalf("finding=%+v err=%v", finding, err)
	}

	appendPool := storeFakePool{conn: storeFakeConn{}}
	if err := NewPostgresTriageRepository(appendPool).AppendHistory(ctx, domain.TriageHistoryRecord{
		FindingID: "cv-1", Decision: "accepted_risk", Justification: "low impact",
		Actor: "alice", RecordedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	historyRows := &fakeRows{data: [][]any{
		{"accepted_risk", "low impact", "alice", "bob", now},
		{"in_progress", "review", "alice", "", now.Add(-time.Hour)},
	}}
	historyPool := storeFakePool{conn: storeFakeConn{}, rows: historyRows}
	history, page, err := NewPostgresTriageRepository(historyPool).ListHistory(ctx, "cv-1", domain.PageRequest{Limit: 1, Cursor: now.Format(time.RFC3339Nano)})
	if err != nil || len(history) != 1 || page.NextCursor == "" {
		t.Fatalf("history=%+v page=%+v err=%v", history, page, err)
	}

	updatePool := storeFakePool{conn: storeFakeConn{}}
	if err := NewPostgresTriageRepository(updatePool).UpdateRiskContext(ctx, domain.RiskContextTriageUpdate{
		FindingID: "cv-1", EffectiveState: "accepted_risk", TriagedBy: "alice",
		TriagedAt: now, RiskScore: 30,
	}); err != nil {
		t.Fatal(err)
	}

	expiredRows := &fakeRows{data: [][]any{{"cv-expired"}}}
	expiredPool := storeFakePool{conn: storeFakeConn{}, rows: expiredRows}
	ids, err := NewPostgresTriageRepository(expiredPool).ListExpiredAcceptedRiskFindings(ctx, now)
	if err != nil || len(ids) != 1 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}

	decisionPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"accepted_risk"}}},
	}}
	decision, err := NewPostgresTriageRepository(decisionPool).LatestDecision(ctx, "cv-1")
	if err != nil || decision != "accepted_risk" {
		t.Fatalf("decision=%q err=%v", decision, err)
	}

	emptyDecisionPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	decision, err = NewPostgresTriageRepository(emptyDecisionPool).LatestDecision(ctx, "cv-1")
	if err != nil || decision != "" {
		t.Fatalf("decision=%q err=%v", decision, err)
	}

	notFoundPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	if _, err := NewPostgresTriageRepository(notFoundPool).GetFindingScope(ctx, "missing"); err == nil {
		t.Fatal("expected finding not found")
	}
}

func TestPostgresTriageVEXGenerator(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	pool := &scriptedFakePool{}
	pool.addExec(1, nil)
	pool.addQueryRow("vuln-1")
	pool.addQueryRow("cvn-1")
	pool.addExec(1, nil)

	vexID, err := NewPostgresTriageVEXGenerator(pool).CreateFromDecision(ctx, domain.GeneratedVEXInput{
		Issuer: "alice", DocumentTime: now,
		Finding: domain.TriageFindingContext{
			FindingID: "cv-1", SBOMDocumentID: "sbom-1", SBOMChecksum: "checksum",
		},
		Assertion: domain.ParsedVEXAssertion{
			CVEID: "CVE-1", ComponentPURL: "pkg:npm/a@1", Status: "not_affected", Justification: "fixed",
		},
	})
	if err != nil || vexID == "" {
		t.Fatalf("vexID=%q err=%v", vexID, err)
	}
}

func TestBuildThemisGeneratedVEX(t *testing.T) {
	raw, checksum, err := buildThemisGeneratedVEX(domain.GeneratedVEXInput{
		Issuer: "alice", DocumentTime: time.Now().UTC(),
		Finding: domain.TriageFindingContext{FindingID: "cv-1"},
		Assertion: domain.ParsedVEXAssertion{
			CVEID: "CVE-1", ComponentPURL: "pkg:npm/a@1", Status: "not_affected",
		},
	})
	if err != nil || len(raw) == 0 || checksum == "" {
		t.Fatalf("raw=%d checksum=%q err=%v", len(raw), checksum, err)
	}
}

func TestLookupHelpersTriage(t *testing.T) {
	ctx := context.Background()
	vulnPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"vuln-1"}}},
	}}
	id, err := lookupVulnerabilityID(ctx, vulnPool, "CVE-1")
	if err != nil || id != "vuln-1" {
		t.Fatalf("id=%q err=%v", id, err)
	}

	cvnPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"cvn-1"}}},
	}}
	cvnID, err := lookupComponentVersionID(ctx, cvnPool, "sbom-1", "pkg:npm/a@1")
	if err != nil || cvnID != "cvn-1" {
		t.Fatalf("id=%q err=%v", cvnID, err)
	}

	if _, err := lookupVulnerabilityID(ctx, storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}, "CVE-404"); err == nil {
		t.Fatal("expected vulnerability not found")
	}
	if _, err := lookupComponentVersionID(ctx, storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}, "sbom-1", "missing"); err == nil {
		t.Fatal("expected component not found")
	}
}

func TestPostgresTriageConstructors(t *testing.T) {
	if NewPostgresTriageRepository(nil) == nil {
		t.Fatal("expected triage repository")
	}
	if NewPostgresTriageVEXGenerator(nil) == nil {
		t.Fatal("expected triage vex generator")
	}
}

func TestPostgresTriageRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	queryErr := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed"), execErr: errors.New("exec failed")}}
	repo := NewPostgresTriageRepository(queryErr)
	if _, err := repo.GetFindingContext(ctx, "cv-1"); err == nil {
		t.Fatal("expected get finding context error")
	}
	if err := repo.AppendHistory(ctx, domain.TriageHistoryRecord{}); err == nil {
		t.Fatal("expected append history error")
	}
}
