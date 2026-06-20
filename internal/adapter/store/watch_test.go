package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

func TestPostgresWatchRepository(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	catalogRows := &fakeRows{data: [][]any{
		{"cvn-1", "pkg:npm/a@1", "a", "npm", "1.0.0", "prod-1", "proj-1", "art-1", "scan-1"},
	}}
	catalogPool := storeFakePool{conn: storeFakeConn{}, rows: catalogRows}
	entries, err := NewPostgresWatchRepository(catalogPool).ListWatchCatalog(ctx)
	if err != nil || len(entries) != 1 || entries[0].PURL != "pkg:npm/a@1" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}

	lastSuccessPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{now}}},
	}}
	ts, err := NewPostgresWatchRepository(lastSuccessPool).GetLastSuccessTimestamp(ctx)
	if err != nil || !ts.Equal(now.UTC()) {
		t.Fatalf("ts=%v err=%v", ts, err)
	}

	emptyTSPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	emptyTS, err := NewPostgresWatchRepository(emptyTSPool).GetLastSuccessTimestamp(ctx)
	if err != nil || !emptyTS.IsZero() {
		t.Fatalf("ts=%v err=%v", emptyTS, err)
	}

	setPool := storeFakePool{conn: storeFakeConn{}}
	if err := NewPostgresWatchRepository(setPool).SetLastSuccessTimestamp(ctx, now); err != nil {
		t.Fatal(err)
	}

	hasPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{true}}},
	}}
	has, err := NewPostgresWatchRepository(hasPool).HasFinding(ctx, "cvn-1", "CVE-1")
	if err != nil || !has {
		t.Fatalf("has=%v err=%v", has, err)
	}

	upsertPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"vuln-1"}}},
	}}
	vulnID, err := NewPostgresWatchRepository(upsertPool).UpsertVulnerability(ctx, domain.VulnerabilityRecord{
		CVEID: "CVE-1", Ecosystem: "npm", PackageName: "a",
	})
	if err != nil || vulnID != "vuln-1" {
		t.Fatalf("vulnID=%q err=%v", vulnID, err)
	}

	listRecordsPool := storeFakePool{conn: storeFakeConn{}, rows: &fakeRows{data: [][]any{
		{"id-1", "CVE-1", "high", 7.0, "", "npm", "a", []string{"1.0.0"}, []string{}, "npm:a@1.0.0"},
	}}}
	records, err := NewPostgresWatchRepository(listRecordsPool).ListVulnerabilityRecords(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestPostgresWatchRepositoryCreateWatchFinding(t *testing.T) {
	ctx := context.Background()

	existingPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{true}}},
	}}
	result, err := NewPostgresWatchRepository(existingPool).CreateWatchFinding(ctx, domain.CreateWatchFindingInput{
		ComponentVersionID: "cvn-1", CVEID: "CVE-1",
	})
	if err != nil || result.Created {
		t.Fatalf("result=%+v err=%v", result, err)
	}

	createPool := &scriptedFakePool{}
	createPool.addQueryRow(false)
	createPool.addQueryRow("cv-1")
	createPool.addExec(1, nil)
	createPool.addExec(1, nil)
	result, err = NewPostgresWatchRepository(createPool).CreateWatchFinding(ctx, domain.CreateWatchFindingInput{
		ComponentVersionID: "cvn-1", CVEID: "CVE-2", VulnerabilityID: "vuln-2",
		ScanReportID: "scan-1", ArtifactID: "art-1", Severity: "high", ProductID: "prod-1", ProjectID: "proj-1",
		ComponentPURL: "pkg:npm/a@1",
	})
	if err != nil || !result.Created || result.ComponentVulnerabilityID != "cv-1" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestPostgresWatchRepositoryConstructor(t *testing.T) {
	if NewPostgresWatchRepository(nil) == nil {
		t.Fatal("expected watch repository")
	}
}

func TestPostgresWatchRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	queryErr := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed"), execErr: errors.New("exec failed")}}
	repo := NewPostgresWatchRepository(queryErr)
	if _, err := repo.ListWatchCatalog(ctx); err == nil {
		t.Fatal("expected list watch catalog error")
	}
	if _, err := repo.GetLastSuccessTimestamp(ctx); err == nil {
		t.Fatal("expected get last success error")
	}
	if err := repo.SetLastSuccessTimestamp(ctx, time.Now()); err == nil {
		t.Fatal("expected set last success error")
	}
}
