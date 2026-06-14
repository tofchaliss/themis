package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

func TestPostgresSBOMManagementRepository(t *testing.T) {
	ctx := context.Background()
	uploaded := time.Now().UTC()

	listPool := &scriptedFakePool{}
	listPool.addQueryRow(2)
	listPool.addQuery([][]any{
		{"sbom-1", "prod-1", "alpha", "1.0.0", "repo/app", "sha256:abc", "cyclonedx", true, uploaded, 10, 3},
		{"sbom-2", "prod-1", "alpha", "1.0.0", "repo/app", "sha256:def", "spdx", false, uploaded.Add(-time.Hour), 5, 1},
	})
	items, total, page, err := NewPostgresSBOMManagementRepository(listPool).ListSBOMs(ctx, domain.PageRequest{Limit: 1})
	if err != nil || total != 2 || len(items) != 1 || page.NextCursor == "" {
		t.Fatalf("items=%+v total=%d page=%+v err=%v", items, total, page, err)
	}

	productPool := &scriptedFakePool{}
	productPool.addQueryRow("prod-1", "alpha", "", time.Now().UTC())
	productPool.addQueryRow(1)
	productPool.addQuery([][]any{
		{"sbom-1", "prod-1", "alpha", "", "repo/app", "sha256:abc", "cyclonedx", true, uploaded, 1, 0},
	})
	productItems, _, _, err := NewPostgresSBOMManagementRepository(productPool).ListProductSBOMs(ctx, "prod-1", domain.PageRequest{Limit: 50})
	if err != nil || len(productItems) != 1 {
		t.Fatalf("items=%+v err=%v", productItems, err)
	}

	cursorPool := &scriptedFakePool{}
	cursorPool.addQueryRow(1)
	cursorPool.addQuery([][]any{
		{"sbom-1", "prod-1", "alpha", "", "repo/app", "sha256:abc", "cyclonedx", true, uploaded, 1, 0},
	})
	cursor := uploaded.UTC().Format(time.RFC3339Nano) + "|sbom-1"
	_, _, _, err = NewPostgresSBOMManagementRepository(cursorPool).ListSBOMs(ctx, domain.PageRequest{Limit: 50, Cursor: cursor})
	if err != nil {
		t.Fatal(err)
	}

	badCursorPool := storeFakePool{conn: storeFakeConn{}}
	_, _, _, err = NewPostgresSBOMManagementRepository(badCursorPool).ListSBOMs(ctx, domain.PageRequest{Cursor: "bad|id"})
	if err == nil {
		t.Fatal("expected invalid cursor error")
	}

	missingProduct := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	_, _, _, err = NewPostgresSBOMManagementRepository(missingProduct).ListProductSBOMs(ctx, "missing", domain.PageRequest{})
	if !errors.Is(err, domain.ErrProductNotFound) {
		t.Fatalf("err=%v", err)
	}
}

func TestPostgresSBOMManagementSoftDelete(t *testing.T) {
	ctx := context.Background()

	successPool := &scriptedFakePool{}
	successPool.addQueryRow(false, nil)
	successPool.addQueryRow(5, 2)
	successPool.addExec(1, nil)
	summary, err := NewPostgresSBOMManagementRepository(successPool).SoftDeleteSBOM(ctx, "sbom-1", true)
	if err != nil || summary.ComponentCount != 5 || summary.FindingCount != 2 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}

	notFoundPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	if _, err := NewPostgresSBOMManagementRepository(notFoundPool).SoftDeleteSBOM(ctx, "missing", false); !errors.Is(err, domain.ErrSBOMNotFound) {
		t.Fatalf("err=%v", err)
	}

	deletedAt := time.Now().UTC()
	alreadyDeleted := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{false, deletedAt}}},
	}}
	if _, err := NewPostgresSBOMManagementRepository(alreadyDeleted).SoftDeleteSBOM(ctx, "sbom-1", false); !errors.Is(err, domain.ErrSBOMNotFound) {
		t.Fatalf("err=%v", err)
	}

	latestPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{true, nil}}},
	}}
	if _, err := NewPostgresSBOMManagementRepository(latestPool).SoftDeleteSBOM(ctx, "sbom-1", false); !errors.Is(err, domain.ErrCannotDeleteLatestSBOM) {
		t.Fatalf("err=%v", err)
	}

	noRowsPool := &scriptedFakePool{}
	noRowsPool.addQueryRow(false, nil)
	noRowsPool.addQueryRow(1, 0)
	noRowsPool.addExec(0, nil)
	if _, err := NewPostgresSBOMManagementRepository(noRowsPool).SoftDeleteSBOM(ctx, "sbom-1", true); !errors.Is(err, domain.ErrSBOMNotFound) {
		t.Fatalf("err=%v", err)
	}
}

func TestPostgresSBOMManagementConstructor(t *testing.T) {
	if NewPostgresSBOMManagementRepository(nil) == nil {
		t.Fatal("expected sbom management repository")
	}
}
