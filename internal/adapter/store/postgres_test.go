package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/themis-project/themis/internal/domain"
)

type scanRow struct {
	values []any
}

func (r scanRow) Scan(dest ...any) error {
	for i, d := range dest {
		switch ptr := d.(type) {
		case *string:
			*ptr = r.values[i].(string)
		case *[]byte:
			*ptr = r.values[i].([]byte)
		}
	}
	return nil
}

type seqFakeConn struct {
	rows []pgx.Row
	idx  int
	exec storeFakeConn
}

func (c *seqFakeConn) nextRow() pgx.Row {
	if c.idx >= len(c.rows) {
		return errRow{err: errors.New("unexpected query")}
	}
	row := c.rows[c.idx]
	c.idx++
	return row
}

type seqFakePool struct {
	conn *seqFakeConn
	rows *fakeRows
}

func (p seqFakePool) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return p.conn.nextRow()
}

func (p seqFakePool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return p.conn.exec.Exec(ctx, sql, args...)
}

func (p seqFakePool) Query(context.Context, string, ...any) (pgx.Rows, error) {
	if p.rows == nil {
		return errRows{err: p.conn.exec.queryErr}, p.conn.exec.queryErr
	}
	return p.rows, nil
}

func TestVulnerabilityIdentityFromDescription(t *testing.T) {
	eco, name := vulnerabilityIdentity("", "", "npm:lodash@1.0.0")
	if eco != "npm" || name != "lodash" {
		t.Fatalf("identity = %q/%q", eco, name)
	}
	eco, name = vulnerabilityIdentity("pypi", "requests", "ignored")
	if eco != "pypi" || name != "requests" {
		t.Fatalf("structured identity = %q/%q", eco, name)
	}
}

func TestPostgresVulnerabilityCatalogFindMatchesFromDescription(t *testing.T) {
	ctx := context.Background()
	rows := &fakeRows{data: [][]any{
		{"id-1", "CVE-1", "high", 7.0, "vector", "", "", []string{"< 2.0.0"}, "npm:lodash@< 2.0.0"},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	catalog := &PostgresVulnerabilityCatalog{pool: pool}

	matches, err := catalog.FindMatches(ctx, "npm", "lodash", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].CVEID != "CVE-1" {
		t.Fatalf("matches = %+v", matches)
	}
}

func TestPostgresVulnerabilityCatalogListForMatching(t *testing.T) {
	ctx := context.Background()
	rows := &fakeRows{data: [][]any{
		{"id-1", "CVE-1", "high", 7.0, "vector", "", "", []string{"1.0.0"}, []string{"2.0.0"}, "npm:lodash@1.0.0"},
		{"id-2", "CVE-2", "low", 1.0, "", "", "", []string{}, []string{}, "not-parseable"},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	catalog := &PostgresVulnerabilityCatalog{pool: pool}

	records, err := catalog.ListForMatching(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].PackageName != "lodash" {
		t.Fatalf("records = %+v", records)
	}
}

func TestPostgresVulnerabilityCatalogFindMatches(t *testing.T) {
	ctx := context.Background()
	rows := &fakeRows{data: [][]any{
		{"id-1", "CVE-1", "high", 7.0, "vector", "npm", "lodash", []string{"1.0.0"}, "npm:lodash@1.0.0"},
	}}
	pool := storeFakePool{conn: storeFakeConn{}, rows: rows}
	catalog := &PostgresVulnerabilityCatalog{pool: pool}

	matches, err := catalog.FindMatches(ctx, "npm", "lodash", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].CVEID != "CVE-1" {
		t.Fatalf("matches = %+v", matches)
	}
}

type fakeRows struct {
	data [][]any
	idx  int
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) Next() bool {
	if r.idx >= len(r.data) {
		return false
	}
	r.idx++
	return true
}
func (r *fakeRows) Scan(dest ...any) error {
	row := r.data[r.idx-1]
	for i, value := range row {
		switch d := dest[i].(type) {
		case *string:
			*d = value.(string)
		case *float64:
			*d = value.(float64)
		case *[]string:
			*d = value.([]string)
		}
	}
	return nil
}
func (r *fakeRows) CommandTag() pgconn.CommandTag              { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Values() ([]any, error)                     { return nil, nil }
func (r *fakeRows) Conn() *pgx.Conn                            { return nil }

type storeFakeConn struct {
	queryErr error
	execErr  error
}

func (f storeFakeConn) QueryRow(context.Context, string, ...any) pgx.Row {
	return errRow{err: f.queryErr}
}

func (f storeFakeConn) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, f.execErr
}

type storeFakePool struct {
	conn storeFakeConn
	rows *fakeRows
}

func (p storeFakePool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return p.conn.QueryRow(ctx, sql, args...)
}

func (p storeFakePool) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return p.conn.Exec(ctx, sql, args...)
}

func (p storeFakePool) Query(context.Context, string, ...any) (pgx.Rows, error) {
	if p.rows == nil {
		return errRows{err: p.conn.queryErr}, p.conn.queryErr
	}
	return p.rows, nil
}

type errRows struct {
	err error
}

func (errRows) Close()                                       {}
func (errRows) Err() error                                   { return nil }
func (errRows) Next() bool                                   { return false }
func (errRows) Scan(...any) error                            { return errors.New("scan") }
func (errRows) CommandTag() pgconn.CommandTag              { return pgconn.CommandTag{} }
func (errRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (errRows) RawValues() [][]byte                          { return nil }
func (e errRows) Values() ([]any, error)                     { return nil, e.err }
func (e errRows) Conn() *pgx.Conn                            { return nil }

func TestPostgresSBOMStoreErrors(t *testing.T) {
	ctx := context.Background()
	pool := storeFakePool{conn: storeFakeConn{execErr: errors.New("exec failed")}}
	store := &PostgresSBOMStore{pool: pool}

	if _, err := store.SaveSBOM(ctx, domain.SaveSBOMInput{Format: "cyclonedx", RawDocument: []byte("{}")}); err == nil {
		t.Fatal("expected save sbom error")
	}
	if _, err := store.SaveVEX(ctx, domain.SaveVEXInput{Format: "openvex", RawDocument: []byte("{}")}); err == nil {
		t.Fatal("expected save vex error")
	}

	findPool := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}
	findStore := &PostgresSBOMStore{pool: findPool}
	if _, err := findStore.FindDocumentIDByChecksum(ctx, "abc"); err == nil {
		t.Fatal("expected find sbom error")
	}
}

func TestPostgresIngestionRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	pool := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed"), execErr: errors.New("exec failed")}}
	repo := &PostgresIngestionRepository{pool: pool}

	if _, found, err := repo.FindByIdempotencyKey(ctx, "key"); err == nil || found {
		t.Fatal("expected find error")
	}
	if err := repo.Create(ctx, domain.IngestionRecord{JobType: domain.JobTypeIngestSBOM}); err == nil {
		t.Fatal("expected create error")
	}
	if err := repo.UpdateStatus(ctx, "id", domain.IngestionStatusFailed, "failed", ""); err == nil {
		t.Fatal("expected update error")
	}
	if _, err := repo.Get(ctx, "id"); err == nil {
		t.Fatal("expected get error")
	}
}

func TestDecodeIngestionPayloadError(t *testing.T) {
	if _, err := decodeIngestionRecord("id", "ingest_sbom", "running", []byte("{")); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestPostgresVulnerabilityCatalogErrors(t *testing.T) {
	ctx := context.Background()
	pool := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed"), execErr: errors.New("exec failed")}}
	catalog := &PostgresVulnerabilityCatalog{pool: pool}

	if _, err := catalog.FindMatches(ctx, "npm", "lodash", "1.0.0"); err == nil {
		t.Fatal("expected find matches error")
	}
	if _, err := catalog.Upsert(ctx, domain.VulnerabilityRecord{CVEID: "CVE-1"}); err == nil {
		t.Fatal("expected upsert error")
	}
}

func TestPostgresCorrelationRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	pool := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed"), execErr: errors.New("exec failed")}}
	repo := &PostgresCorrelationRepository{pool: pool}

	if _, err := repo.CreateFinding(ctx, "a", "b", "c"); err == nil {
		t.Fatal("expected create finding error")
	}
	if _, err := repo.ListFindings(ctx, "scan"); err == nil {
		t.Fatal("expected list findings error")
	}
}

func TestPostgresRiskContextRepositoryErrors(t *testing.T) {
	ctx := context.Background()
	pool := storeFakePool{conn: storeFakeConn{execErr: errors.New("exec failed")}}
	repo := &PostgresRiskContextRepository{pool: pool}
	if _, err := repo.CreateForFinding(ctx, "finding", "high"); err == nil {
		t.Fatal("expected create risk context error")
	}
}

func TestPostgresComponentStoreErrors(t *testing.T) {
	ctx := context.Background()
	pool := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}
	store := &PostgresComponentStore{pool: pool}
	if _, err := store.UpsertFromCanonical(ctx, "scan", domain.CanonicalSBOM{
		Components: []domain.CanonicalComponent{{PURL: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm"}},
	}); err == nil {
		t.Fatal("expected upsert components error")
	}
}

func TestPostgresIngestionRepositorySuccess(t *testing.T) {
	ctx := context.Background()
	payload, err := json.Marshal(ingestionPayload{
		IdempotencyKey: "key-1",
		PipelineStatus: string(domain.IngestionStatusCorrelating),
		ScanID:         "scan-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	findPool := seqFakePool{conn: &seqFakeConn{rows: []pgx.Row{
		scanRow{values: []any{"job-1", "ingest_sbom", "running", payload}},
	}}}
	repo := &PostgresIngestionRepository{pool: findPool}
	record, found, err := repo.FindByIdempotencyKey(ctx, "key-1")
	if err != nil || !found || record.ID != "job-1" {
		t.Fatalf("record = %+v found=%v err=%v", record, found, err)
	}

	notFoundPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	notFoundRepo := &PostgresIngestionRepository{pool: notFoundPool}
	if _, found, err := notFoundRepo.FindByIdempotencyKey(ctx, "missing"); err != nil || found {
		t.Fatalf("expected not found, found=%v err=%v", found, err)
	}

	createPool := storeFakePool{conn: storeFakeConn{}}
	if err := (&PostgresIngestionRepository{pool: createPool}).Create(ctx, domain.IngestionRecord{
		JobType: domain.JobTypeIngestSBOM, IdempotencyKey: "key-2",
	}); err != nil {
		t.Fatal(err)
	}

	getPayload, err := encodeIngestionPayload(domain.IngestionRecord{
		ID: "job-2", JobType: domain.JobTypeIngestSBOM, Status: domain.IngestionStatusEnriching,
	})
	if err != nil {
		t.Fatal(err)
	}
	updatePool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{
			scanRow{values: []any{"ingest_sbom", "running", getPayload}},
		},
	}}
	updateRepo := &PostgresIngestionRepository{pool: updatePool}
	if err := updateRepo.UpdateStatus(ctx, "job-2", domain.IngestionStatusCompleted, "", "scan-2"); err != nil {
		t.Fatal(err)
	}

	getPool := seqFakePool{conn: &seqFakeConn{rows: []pgx.Row{
		scanRow{values: []any{"ingest_sbom", "completed", getPayload}},
	}}}
	got, err := (&PostgresIngestionRepository{pool: getPool}).Get(ctx, "job-2")
	if err != nil || got.Status != domain.IngestionStatusEnriching {
		t.Fatalf("got = %+v err=%v", got, err)
	}

	missingGetPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	if _, err := (&PostgresIngestionRepository{pool: missingGetPool}).Get(ctx, "missing"); err == nil {
		t.Fatal("expected get error")
	}
}

func TestPostgresSBOMStoreSuccess(t *testing.T) {
	ctx := context.Background()
	pool := storeFakePool{conn: storeFakeConn{}}
	sbomStore := &PostgresSBOMStore{pool: pool}

	id, err := sbomStore.SaveSBOM(ctx, domain.SaveSBOMInput{
		Format: "cyclonedx", RawDocument: []byte("{}"), TrustResult: domain.TrustResult{Status: domain.TrustStatusVerified},
	})
	if err != nil || id == "" {
		t.Fatalf("SaveSBOM() id=%q err=%v", id, err)
	}
	vexID, err := sbomStore.SaveVEX(ctx, domain.SaveVEXInput{
		Format: "openvex", RawDocument: []byte("{}"), TrustResult: domain.TrustResult{Status: domain.TrustStatusVerified},
	})
	if err != nil || vexID == "" {
		t.Fatalf("SaveVEX() id=%q err=%v", vexID, err)
	}

	findPool := seqFakePool{conn: &seqFakeConn{rows: []pgx.Row{
		scanRow{values: []any{"doc-1"}},
	}}}
	found, err := (&PostgresSBOMStore{pool: findPool}).FindDocumentIDByChecksum(ctx, "abc")
	if err != nil || found != "doc-1" {
		t.Fatalf("found=%q err=%v", found, err)
	}

	notFoundPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	if _, err := (&PostgresSBOMStore{pool: notFoundPool}).FindDocumentIDByChecksum(ctx, "missing"); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestPostgresComponentStoreSuccess(t *testing.T) {
	ctx := context.Background()
	pool := seqFakePool{conn: &seqFakeConn{rows: []pgx.Row{
		scanRow{values: []any{"component-1"}},
		scanRow{values: []any{"version-1"}},
	}}}
	store := &PostgresComponentStore{pool: pool}
	ids, err := store.UpsertFromCanonical(ctx, "scan-1", domain.CanonicalSBOM{
		Components: []domain.CanonicalComponent{{
			PURL: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Ecosystem: "npm",
		}},
	})
	if err != nil || ids["pkg:npm/lodash@4.17.21"] != "version-1" {
		t.Fatalf("ids = %+v err=%v", ids, err)
	}
}

func TestPostgresVulnerabilityCatalogSuccess(t *testing.T) {
	ctx := context.Background()
	upsertPool := seqFakePool{conn: &seqFakeConn{rows: []pgx.Row{
		scanRow{values: []any{"vuln-1"}},
	}}}
	id, err := (&PostgresVulnerabilityCatalog{pool: upsertPool}).Upsert(ctx, domain.VulnerabilityRecord{
		CVEID: "CVE-1", Severity: "high", Ecosystem: "npm", PackageName: "lodash",
	})
	if err != nil || id != "vuln-1" {
		t.Fatalf("id=%q err=%v", id, err)
	}

	nilSlicePool := seqFakePool{conn: &seqFakeConn{rows: []pgx.Row{
		scanRow{values: []any{"vuln-2"}},
	}}}
	if _, err := (&PostgresVulnerabilityCatalog{pool: nilSlicePool}).Upsert(ctx, domain.VulnerabilityRecord{
		CVEID: "CVE-2", Ecosystem: "npm", PackageName: "express",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresCorrelationRepositorySuccess(t *testing.T) {
	ctx := context.Background()
	createPool := seqFakePool{conn: &seqFakeConn{rows: []pgx.Row{
		scanRow{values: []any{"finding-1"}},
	}}}
	id, err := (&PostgresCorrelationRepository{pool: createPool}).CreateFinding(ctx, "cv", "vuln", "sbom")
	if err != nil || id != "finding-1" {
		t.Fatalf("id=%q err=%v", id, err)
	}

	listPool := seqFakePool{rows: &fakeRows{data: [][]any{
		{"finding-1", "high"},
		{"finding-2", "unknown"},
	}}}
	findings, err := (&PostgresCorrelationRepository{pool: listPool}).ListFindings(ctx, "sbom")
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings = %+v err=%v", findings, err)
	}
}

func TestPostgresRiskContextRepositorySuccess(t *testing.T) {
	ctx := context.Background()
	pool := storeFakePool{conn: storeFakeConn{}}
	id, err := (&PostgresRiskContextRepository{pool: pool}).CreateForFinding(ctx, "finding-1", "high")
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestDecodeIngestionRecordEmptyPipelineStatus(t *testing.T) {
	record, err := decodeIngestionRecord("id", "ingest_sbom", "completed", nil)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != domain.IngestionStatusCompleted {
		t.Fatalf("status = %q", record.Status)
	}
}

func TestStaticVulnerabilityFetcherEmptyAffected(t *testing.T) {
	fetcher := StaticVulnerabilityFetcher{Records: []domain.VulnerabilityRecord{
		{CVEID: "CVE-1", Ecosystem: "npm", PackageName: "lodash"},
	}}
	out, err := fetcher.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "npm", Name: "lodash", Version: "1.0.0",
	})
	if err != nil || len(out) != 1 || out[0].AffectedVersions[0] != "1.0.0" {
		t.Fatalf("out = %+v err=%v", out, err)
	}
}
