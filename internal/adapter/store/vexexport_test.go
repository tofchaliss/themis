package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

func TestPostgresVEXExportRepository(t *testing.T) {
	ctx := context.Background()
	created := time.Now().UTC()
	level := "High"
	epss := 0.5

	existsPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{true}}},
	}}
	exists, err := NewPostgresVEXExportRepository(existsPool).ProductExists(ctx, "prod-1")
	if err != nil || !exists {
		t.Fatalf("exists=%v err=%v", exists, err)
	}

	versionPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"pv-1", "prod-1", "1.0.0", "released", created, created}}},
	}}
	version, err := NewPostgresVEXExportRepository(versionPool).GetProductVersion(ctx, "prod-1", "1.0.0")
	if err != nil || version.ID != "pv-1" {
		t.Fatalf("version=%+v err=%v", version, err)
	}

	notFoundPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	if _, err := NewPostgresVEXExportRepository(notFoundPool).GetProductVersion(ctx, "prod-1", "9.9.9"); !errors.Is(err, domain.ErrProductVersionNotFound) {
		t.Fatalf("err=%v", err)
	}

	findingsRows := &fakeRows{data: [][]any{{
		"cv-1", "pkg:npm/a@1", "CVE-1", "high", 7.5, "vuln-1", "prod-1", "sbom-1", "comp-1",
		"rc-1", "detected", "high", "not_affected", "va-1", "justified",
		float64(70), epss, true, false, level, 1.2, "covered",
	}}}
	findingsPool := storeFakePool{conn: storeFakeConn{}, rows: findingsRows}
	findings, err := NewPostgresVEXExportRepository(findingsPool).ListFindingsForProductVersion(ctx, "pv-1")
	if err != nil || len(findings) != 1 || findings[0].RiskScore != 70 || findings[0].DeterministicLevel != domain.DeterministicLevelHigh {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}

	assertionRows := &fakeRows{data: [][]any{
		{"va-1", "vex-1", "pkg:npm/a@1", "CVE-1", "not_affected", "fixed", created, "manual"},
	}}
	assertionPool := storeFakePool{conn: storeFakeConn{}, rows: assertionRows}
	assertions, err := NewPostgresVEXExportRepository(assertionPool).ListAssertionsForSBOM(ctx, "sbom-1")
	if err != nil || len(assertions) != 1 {
		t.Fatalf("assertions=%+v err=%v", assertions, err)
	}

	queryErr := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}
	if _, err := NewPostgresVEXExportRepository(queryErr).ListFindingsForProductVersion(ctx, "pv-1"); err == nil {
		t.Fatal("expected list findings error")
	}
}

func TestPostgresVEXExportRepositoryConstructor(t *testing.T) {
	if NewPostgresVEXExportRepository(nil) == nil {
		t.Fatal("expected vex export repository")
	}
}
