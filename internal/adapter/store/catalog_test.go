package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

func TestNormalizeLimit(t *testing.T) {
	if got := normalizeLimit(0); got != 50 {
		t.Fatalf("normalizeLimit(0) = %d", got)
	}
	if got := normalizeLimit(200); got != 100 {
		t.Fatalf("normalizeLimit(200) = %d", got)
	}
	if got := normalizeLimit(25); got != 25 {
		t.Fatalf("normalizeLimit(25) = %d", got)
	}
}

func TestPaginateProducts(t *testing.T) {
	items := []domain.Product{
		{Name: "a"}, {Name: "b"}, {Name: "c"},
	}
	page, next, err := paginateProducts(items, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || next.NextCursor != "b" {
		t.Fatalf("page=%+v next=%+v", page, next)
	}
}

func TestCatalogConstructors(t *testing.T) {
	if NewPostgresProductCatalogRepository(nil) == nil {
		t.Fatal("expected product catalog")
	}
	if NewPostgresScanQueryRepository(nil) == nil {
		t.Fatal("expected scan query repository")
	}
	if NewPostgresComponentCatalogRepository(nil) == nil {
		t.Fatal("expected component catalog")
	}
	if NewPostgresCVEWatchFindingRepository(nil) == nil {
		t.Fatal("expected cve watch repository")
	}
	if NewPostgresNotificationConfigRepository(nil) == nil {
		t.Fatal("expected notification config repository")
	}
	if NewPostgresScannerConfigRepository(nil) == nil {
		t.Fatal("expected scanner config repository")
	}
}

func TestPostgresProductCatalogCreateProduct(t *testing.T) {
	pool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{
			scanRow{values: []any{time.Now().UTC()}}, // INSERT products RETURNING created_at
			scanRow{values: []any{"proj-default"}},   // ensureDefaultProject RETURNING id
		},
		exec: storeFakeConn{},
	}}
	repo := NewPostgresProductCatalogRepository(pool)
	product, err := repo.CreateProduct(context.Background(), "alpha", "desc")
	if err != nil || product.Name != "alpha" || product.ID == "" {
		t.Fatalf("product=%+v err=%v", product, err)
	}
}

func TestPostgresProductCatalogListProducts(t *testing.T) {
	created := time.Now().UTC()
	rows := &fakeRows{data: [][]any{
		{"id-1", "alpha", "desc", created},
		{"id-2", "beta", "", created},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	repo := NewPostgresProductCatalogRepository(pool)

	items, page, err := repo.ListProducts(context.Background(), domain.PageRequest{Limit: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || page.NextCursor != "alpha" {
		t.Fatalf("items=%+v page=%+v", items, page)
	}

	scopedRows := &fakeRows{data: [][]any{{"id-1", "alpha", "desc", created}}}
	scopedPool := storeFakePool{conn: storeFakeConn{}, rows: scopedRows}
	scopedItems, _, err := NewPostgresProductCatalogRepository(scopedPool).ListProducts(
		context.Background(), domain.PageRequest{Limit: 50, Cursor: "a"}, "prod-1",
	)
	if err != nil || len(scopedItems) != 1 {
		t.Fatalf("scoped items=%+v err=%v", scopedItems, err)
	}
}

func TestPostgresProductCatalogGetProduct(t *testing.T) {
	created := time.Now().UTC()
	pool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"prod-1", "alpha", "desc", created}}},
	}}
	repo := NewPostgresProductCatalogRepository(pool)
	item, err := repo.GetProduct(context.Background(), "prod-1")
	if err != nil || item.ID != "prod-1" {
		t.Fatalf("item=%+v err=%v", item, err)
	}

	notFoundPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	_, err = NewPostgresProductCatalogRepository(notFoundPool).GetProduct(context.Background(), "missing")
	if !errors.Is(err, domain.ErrProductNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestPostgresProductCatalogCreateProject(t *testing.T) {
	created := time.Now().UTC()
	pool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{
			scanRow{values: []any{"prod-1", "alpha", "", created}},
			scanRow{values: []any{created}},
		},
	}}
	repo := NewPostgresProductCatalogRepository(pool)
	project, err := repo.CreateProject(context.Background(), "prod-1", "web", "desc")
	if err != nil || project.ProductID != "prod-1" || project.Name != "web" {
		t.Fatalf("project=%+v err=%v", project, err)
	}

	missingProduct := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	_, err = NewPostgresProductCatalogRepository(missingProduct).CreateProject(context.Background(), "missing", "web", "")
	if !errors.Is(err, domain.ErrProductNotFound) {
		t.Fatalf("expected product not found, err=%v", err)
	}
}

func TestPostgresProductCatalogListProjects(t *testing.T) {
	created := time.Now().UTC()
	rows := &fakeRows{data: [][]any{
		{"proj-1", "prod-1", "alpha", "desc", created},
		{"proj-2", "prod-1", "beta", "", created},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	items, page, err := NewPostgresProductCatalogRepository(pool).ListProjects(
		context.Background(), "prod-1", domain.PageRequest{Limit: 1, Cursor: "a"},
	)
	if err != nil || len(items) != 1 || page.NextCursor != "alpha" {
		t.Fatalf("items=%+v page=%+v err=%v", items, page, err)
	}
}

func TestPostgresProductCatalogListProductVersions(t *testing.T) {
	created := time.Now().UTC()
	released := created.Add(-24 * time.Hour)
	rows := &fakeRows{data: [][]any{
		{"pv-1", "prod-1", "1.0.0", "released", released, created},
		{"pv-2", "prod-1", "2.0.0", "draft", nil, created},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	items, page, err := NewPostgresProductCatalogRepository(pool).ListProductVersions(
		context.Background(), "prod-1", domain.PageRequest{Limit: 1, Cursor: "0.9.0"},
	)
	if err != nil || len(items) != 1 || page.NextCursor != "1.0.0" {
		t.Fatalf("items=%+v page=%+v err=%v", items, page, err)
	}
}

func TestPostgresScanQueryListProjectScans(t *testing.T) {
	ingested := time.Now().UTC()
	rows := &fakeRows{data: [][]any{
		{"scan-1", "proj-1", "prod-1", "sha256:abc", "cyclonedx", "verified", ingested, "job-1"},
		{"scan-2", "proj-1", "prod-1", "sha256:def", "spdx", "unsigned", ingested.Add(-time.Hour), ""},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	items, page, err := NewPostgresScanQueryRepository(pool).ListProjectScans(
		context.Background(), "proj-1", domain.PageRequest{Limit: 1, Cursor: ingested.Format(time.RFC3339Nano)},
	)
	if err != nil || len(items) != 1 || page.NextCursor == "" {
		t.Fatalf("items=%+v page=%+v err=%v", items, page, err)
	}
}

func TestPostgresScanQueryGetScan(t *testing.T) {
	ingested := time.Now().UTC()
	pool := &scriptedFakePool{}
	pool.addQueryRow("scan-1", "proj-1", "prod-1", "sha256:abc", "cyclonedx", "verified", ingested, "job-1")
	pool.addQuery([][]any{{"high", 2}, {"low", 1}})
	repo := NewPostgresScanQueryRepository(pool)
	detail, err := repo.GetScan(context.Background(), "scan-1")
	if err != nil || detail.ID != "scan-1" || detail.VulnerabilityCounts["high"] != 2 {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}

	notFound := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	if _, err := NewPostgresScanQueryRepository(notFound).GetScan(context.Background(), "missing"); err == nil {
		t.Fatal("expected get scan error")
	}
}

func TestPostgresScanQueryListScanVulnerabilities(t *testing.T) {
	rows := &fakeRows{data: [][]any{
		{"cv-1", "CVE-1", "high", "open", "pkg:npm/a@1", "prod-1", "1.0.0", "1.2.3"},
		{"cv-2", "CVE-2", "low", "not_affected", "pkg:npm/b@1", "prod-1", "2.0.0", ""},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	items, page, err := NewPostgresScanQueryRepository(pool).ListScanVulnerabilities(
		context.Background(), "scan-1", domain.ScanVulnerabilityFilter{
			Severity: "high", EffectiveState: "open", CVEID: "CVE-1",
		}, domain.PageRequest{Limit: 1, Cursor: "cv-0"},
	)
	if err != nil || len(items) != 1 || page.NextCursor != "cv-1" {
		t.Fatalf("items=%+v page=%+v err=%v", items, page, err)
	}
	if items[0].InstalledVersion != "1.0.0" || items[0].FixedVersion != "1.2.3" {
		t.Fatalf("installed/fixed = %q/%q", items[0].InstalledVersion, items[0].FixedVersion)
	}
}

func TestPostgresScanQueryGetProjectProductID(t *testing.T) {
	pool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{"prod-1"}}},
		exec: storeFakeConn{},
	}}
	repo := NewPostgresScanQueryRepository(pool)
	id, err := repo.GetProjectProductID(context.Background(), "proj-1")
	if err != nil || id != "prod-1" {
		t.Fatalf("id=%q err=%v", id, err)
	}

	notFound := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	if _, err := NewPostgresScanQueryRepository(notFound).GetProjectProductID(context.Background(), "missing"); err == nil {
		t.Fatal("expected project not found error")
	}
}

func TestPostgresComponentCatalogListComponents(t *testing.T) {
	rows := &fakeRows{data: [][]any{
		{"pkg:npm/a@1", "a", "npm", "1.0.0", "prod-1"},
		{"pkg:npm/b@1", "b", "npm", "1.0.0", "prod-1"},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	items, page, err := NewPostgresComponentCatalogRepository(pool).ListComponents(
		context.Background(), "pkg:npm/a@1", "prod-1", domain.PageRequest{Limit: 1, Cursor: "pkg:npm/a"},
	)
	if err != nil || len(items) != 1 || page.NextCursor != "pkg:npm/a@1" {
		t.Fatalf("items=%+v page=%+v err=%v", items, page, err)
	}
}

func TestPostgresCVEWatchFindingRepositoryListFindings(t *testing.T) {
	detected := time.Now().UTC()
	rows := &fakeRows{data: [][]any{
		{"wf-1", "CVE-1", "prod-1", "proj-1", "new", detected},
		{"wf-2", "CVE-2", "prod-1", "", "new", detected},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	items, page, err := NewPostgresCVEWatchFindingRepository(pool).ListFindings(
		context.Background(), "prod-1", "high", domain.PageRequest{Limit: 1, Cursor: "wf-0"},
	)
	if err != nil || len(items) != 1 || page.NextCursor != "wf-1" {
		t.Fatalf("items=%+v page=%+v err=%v", items, page, err)
	}
}

func TestPostgresNotificationConfigRepository(t *testing.T) {
	filterJSON, err := json.Marshal(domain.NotificationRuleFilter{MinSeverity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	rows := &fakeRows{data: [][]any{
		{"rule-1", "alerts", "ingestion_complete", "email", "a@example.com", filterJSON, true},
	}}
	listPool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	rules, err := NewPostgresNotificationConfigRepository(listPool).ListRules(context.Background())
	if err != nil || len(rules) != 1 || rules[0].Filter.MinSeverity != "high" {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}

	replacePool := storeFakePool{conn: storeFakeConn{rowsAffected: 1}}
	err = NewPostgresNotificationConfigRepository(replacePool).ReplaceRules(context.Background(), []domain.NotificationRule{
		{Name: "alerts", EventType: "ingestion_complete", Channel: "email", Destination: "a@example.com", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	execErrPool := storeFakePool{conn: storeFakeConn{execErr: errors.New("exec failed")}}
	if err := NewPostgresNotificationConfigRepository(execErrPool).ReplaceRules(context.Background(), nil); err == nil {
		t.Fatal("expected replace rules error")
	}
}

func TestPostgresScannerConfigRepository(t *testing.T) {
	settingsJSON, err := json.Marshal(domain.ScannerSettings{MaxComponents: 1000})
	if err != nil {
		t.Fatal(err)
	}
	pool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{settingsJSON}}},
		exec: storeFakeConn{},
	}}
	repo := NewPostgresScannerConfigRepository(pool)
	settings, err := repo.Get(context.Background())
	if err != nil || settings.MaxComponents != 1000 {
		t.Fatalf("settings=%+v err=%v", settings, err)
	}

	defaultPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	defaultSettings, err := NewPostgresScannerConfigRepository(defaultPool).Get(context.Background())
	if err != nil || defaultSettings.MaxComponents != defaultScannerSettings().MaxComponents {
		t.Fatalf("settings=%+v err=%v", defaultSettings, err)
	}

	badJSONPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{[]byte("{")}}},
	}}
	if _, err := NewPostgresScannerConfigRepository(badJSONPool).Get(context.Background()); err == nil {
		t.Fatal("expected decode error")
	}

	savePool := storeFakePool{conn: storeFakeConn{}}
	if err := NewPostgresScannerConfigRepository(savePool).Save(context.Background(), defaultScannerSettings()); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresAPIKeyFindByHashPrefix(t *testing.T) {
	repo := &PostgresAPIKeyRepository{pool: storeFakePool{conn: storeFakeConn{}}}
	if _, err := repo.FindByHashPrefix(context.Background()); err == nil {
		t.Fatal("expected not implemented error")
	}
}

func TestCatalogListErrors(t *testing.T) {
	ctx := context.Background()
	queryErr := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}

	if _, _, err := NewPostgresProductCatalogRepository(queryErr).ListProducts(ctx, domain.PageRequest{}, ""); err == nil {
		t.Fatal("expected list products error")
	}
	if _, _, err := NewPostgresProductCatalogRepository(queryErr).ListProjects(ctx, "prod-1", domain.PageRequest{}); err == nil {
		t.Fatal("expected list projects error")
	}
	if _, _, err := NewPostgresScanQueryRepository(queryErr).ListProjectScans(ctx, "proj-1", domain.PageRequest{}); err == nil {
		t.Fatal("expected list scans error")
	}
	if _, err := NewPostgresNotificationConfigRepository(queryErr).ListRules(ctx); err == nil {
		t.Fatal("expected list rules error")
	}
}
