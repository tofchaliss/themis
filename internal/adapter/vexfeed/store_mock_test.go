//go:build integration

package vexfeed

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/domain"
)

type mockRow struct {
	err error
	val any
}

func (m mockRow) Scan(dest ...any) error {
	if m.err != nil {
		return m.err
	}
	for i, d := range dest {
		switch x := d.(type) {
		case *string:
			if s, ok := m.val.(string); ok && i == 0 {
				*x = s
			} else {
				*x = "generated-id"
			}
		}
	}
	return nil
}

type mockRows struct {
	data [][]string
	idx  int
	err  error
}

func (m *mockRows) Close()                                       {}
func (m *mockRows) Conn() *pgx.Conn                              { return nil }
func (m *mockRows) Err() error                                   { return m.err }
func (m *mockRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (m *mockRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (m *mockRows) Next() bool {
	if m.idx >= len(m.data) {
		return false
	}
	m.idx++
	return true
}
func (m *mockRows) Scan(dest ...any) error {
	if m.idx == 0 || m.idx > len(m.data) {
		return errors.New("no row")
	}
	row := m.data[m.idx-1]
	for i, d := range dest {
		if i >= len(row) {
			break
		}
		switch x := d.(type) {
		case *string:
			*x = row[i]
		}
	}
	return nil
}
func (m *mockRows) Values() ([]any, error) { return nil, nil }
func (m *mockRows) RawValues() [][]byte    { return nil }

type mockTx struct {
	queryRows []mockRow
	queryIdx  int
	execErrs  []error
	execIdx   int
	commitErr error
}

func (m *mockTx) nextExecErr() error {
	if m.execIdx >= len(m.execErrs) {
		return nil
	}
	err := m.execErrs[m.execIdx]
	m.execIdx++
	return err
}

func (m *mockTx) Begin(context.Context) (pgx.Tx, error) { return nil, errors.New("nested tx") }
func (m *mockTx) Commit(context.Context) error          { return m.commitErr }
func (m *mockTx) Rollback(context.Context) error        { return nil }
func (m *mockTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, nil
}
func (m *mockTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { return nil }
func (m *mockTx) LargeObjects() pgx.LargeObjects                         { return pgx.LargeObjects{} }
func (m *mockTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, nil
}
func (m *mockTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	if err := m.nextExecErr(); err != nil {
		return pgconn.CommandTag{}, err
	}
	return pgconn.NewCommandTag("OK 1"), nil
}
func (m *mockTx) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }
func (m *mockTx) QueryRow(context.Context, string, ...any) pgx.Row {
	if m.queryIdx >= len(m.queryRows) {
		return mockRow{err: pgx.ErrNoRows}
	}
	r := m.queryRows[m.queryIdx]
	m.queryIdx++
	return r
}
func (m *mockTx) Conn() *pgx.Conn { return nil }

type mockPool struct {
	beginErr  error
	tx        *mockTx
	queryErr  error
	queryRows pgx.Rows
}

func (m *mockPool) Begin(context.Context) (pgx.Tx, error) {
	if m.beginErr != nil {
		return nil, m.beginErr
	}
	if m.tx == nil {
		m.tx = &mockTx{}
	}
	return m.tx, nil
}

func (m *mockPool) Query(context.Context, string, ...any) (pgx.Rows, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	if m.queryRows != nil {
		return m.queryRows, nil
	}
	return &mockRows{}, nil
}

func TestNewPostgresAssertionStore(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{})
	if store == nil {
		t.Fatal("expected store")
	}
}

func TestUpsertAssertionsEmpty(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{})
	n, err := store.UpsertAssertions(context.Background(), "feed", nil)
	if err != nil || n != 0 {
		t.Fatalf("UpsertAssertions() = %d, %v", n, err)
	}
}

func TestUpsertAssertionsSuccess(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{tx: &mockTx{
		queryRows: []mockRow{
			{val: "doc-1"},
			{val: "vuln-1"},
		},
	}})
	n, err := store.UpsertAssertions(context.Background(), "alpine", []domain.VendorVEXAssertion{{
		AdvisoryID: "ALP-1", CVEID: "CVE-2024-1", PackageName: "busybox",
		Introduced: "0", Fixed: "1.0", Ecosystem: "Alpine", Status: domain.VEXStatusNotAffected,
	}})
	if err != nil || n != 1 {
		t.Fatalf("UpsertAssertions() = %d, %v", n, err)
	}
}

func TestUpsertAssertionsAlpinePURLFallback(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{tx: &mockTx{
		queryRows: []mockRow{
			{val: "doc-1"},
			{err: pgx.ErrNoRows},
		},
	}})
	n, err := store.UpsertAssertions(context.Background(), "alpine", []domain.VendorVEXAssertion{{
		CVEID: "CVE-2024-2", PackageName: "curl", Status: domain.VEXStatusAffected,
	}})
	if err != nil || n != 1 {
		t.Fatalf("UpsertAssertions() = %d, %v", n, err)
	}
}

func TestUpsertAssertionsBeginError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{beginErr: errors.New("begin failed")})
	_, err := store.UpsertAssertions(context.Background(), "feed", []domain.VendorVEXAssertion{{CVEID: "CVE-1"}})
	if err == nil {
		t.Fatal("expected begin error")
	}
}

func TestUpsertAssertionsDocumentError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{tx: &mockTx{
		queryRows: []mockRow{{err: errors.New("insert doc failed")}},
	}})
	_, err := store.UpsertAssertions(context.Background(), "feed", []domain.VendorVEXAssertion{{CVEID: "CVE-1"}})
	if err == nil {
		t.Fatal("expected document error")
	}
}

func TestUpsertAssertionsDeleteError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{tx: &mockTx{
		queryRows: []mockRow{{val: "doc-1"}},
		execErrs:  []error{errors.New("delete failed")},
	}})
	_, err := store.UpsertAssertions(context.Background(), "feed", []domain.VendorVEXAssertion{{CVEID: "CVE-1"}})
	if err == nil {
		t.Fatal("expected delete error")
	}
}

func TestUpsertAssertionsVulnLookupError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{tx: &mockTx{
		queryRows: []mockRow{
			{val: "doc-1"},
			{err: errors.New("vuln lookup failed")},
		},
	}})
	_, err := store.UpsertAssertions(context.Background(), "feed", []domain.VendorVEXAssertion{{CVEID: "CVE-1"}})
	if err == nil {
		t.Fatal("expected vuln error")
	}
}

func TestUpsertAssertionsInsertAssertionError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{tx: &mockTx{
		queryRows: []mockRow{
			{val: "doc-1"},
			{val: "vuln-1"},
		},
		execErrs: []error{nil, errors.New("insert assertion failed")},
	}})
	_, err := store.UpsertAssertions(context.Background(), "feed", []domain.VendorVEXAssertion{{
		CVEID: "CVE-1", ComponentPURL: "pkg:rpm/redhat/httpd@1.0", Status: domain.VEXStatusNotAffected,
	}})
	if err == nil {
		t.Fatal("expected insert assertion error")
	}
}

func TestUpsertAssertionsCommitError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{tx: &mockTx{
		queryRows: []mockRow{
			{val: "doc-1"},
			{val: "vuln-1"},
		},
		commitErr: errors.New("commit failed"),
	}})
	n, err := store.UpsertAssertions(context.Background(), "feed", []domain.VendorVEXAssertion{{
		CVEID: "CVE-1", ComponentPURL: "pkg:rpm/redhat/httpd@1.0", Status: domain.VEXStatusNotAffected,
	}})
	if err == nil || n != 1 {
		t.Fatalf("UpsertAssertions() = %d, %v", n, err)
	}
}

func TestListAssertionsForCVE(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{queryRows: &mockRows{data: [][]string{{
		"RHSA-1", "pkg:apk/alpine/busybox@1.0", "CVE-2024-1", "not_affected", "component_not_present",
		`{"introduced":"0","fixed":"1.0","package":"busybox","ecosystem":"Alpine"}`,
	}}}})
	out, err := store.ListAssertionsForCVE(context.Background(), "CVE-2024-1")
	if err != nil || len(out) != 1 {
		t.Fatalf("ListAssertionsForCVE() = %v, %v", out, err)
	}
	if out[0].PackageName != "busybox" || out[0].Ecosystem != "Alpine" {
		t.Fatalf("assertion = %+v", out[0])
	}
}

func TestListAssertionsForCVEQueryError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{queryErr: errors.New("query failed")})
	_, err := store.ListAssertionsForCVE(context.Background(), "CVE-1")
	if err == nil {
		t.Fatal("expected query error")
	}
}

func TestListAssertionsForSBOMCVEs(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{queryRows: &mockRows{data: [][]string{{
		"RHSA-1", "pkg:rpm/redhat/httpd@1.0", "CVE-2024-1", "not_affected", "", "",
	}}}})
	out, err := store.ListAssertionsForSBOMCVEs(context.Background(), "sbom-1", []string{"CVE-2024-1", "CVE-404"})
	if err != nil || len(out) != 1 {
		t.Fatalf("ListAssertionsForSBOMCVEs() = %v, %v", out, err)
	}
}

func TestFindSBOMDocumentIDsForCVE(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{queryRows: &mockRows{data: [][]string{{"sbom-1"}, {"sbom-2"}}}})
	ids, err := store.FindSBOMDocumentIDsForCVE(context.Background(), "CVE-1")
	if err != nil || len(ids) != 2 {
		t.Fatalf("FindSBOMDocumentIDsForCVE() = %v, %v", ids, err)
	}
}

func TestFindSBOMDocumentIDsForCVEError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{queryErr: errors.New("query failed")})
	_, err := store.FindSBOMDocumentIDsForCVE(context.Background(), "CVE-1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestScanVendorAssertionsBadImpactJSON(t *testing.T) {
	rows := &mockRows{data: [][]string{{
		"ADV", "pkg:apk/alpine/x@1", "CVE-1", "affected", "", "not-json",
	}}}
	out, err := scanVendorAssertions(rows)
	if err != nil || len(out) != 1 {
		t.Fatalf("scanVendorAssertions() = %v, %v", out, err)
	}
}

func TestNullStr(t *testing.T) {
	if nullStr("") != nil || nullStr("  ") != nil {
		t.Fatal("expected nil for blank")
	}
	if nullStr("x") != "x" {
		t.Fatal("expected value")
	}
}

func TestOsvImpactStatement(t *testing.T) {
	if osvImpactStatement(domain.VendorVEXAssertion{}) != "" {
		t.Fatal("expected empty")
	}
	got := osvImpactStatement(domain.VendorVEXAssertion{Introduced: "0", Fixed: "1.0", PackageName: "busybox", Ecosystem: "Alpine"})
	if got == "" {
		t.Fatal("expected JSON impact")
	}
}

func TestEnrichmentAssertionReader(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{queryRows: &mockRows{data: [][]string{{
		"ADV", "pkg:rpm/redhat/httpd@1.0", "CVE-1", "not_affected", "", "",
	}}}})
	reader := EnrichmentAssertionReader{Store: store}
	out, err := reader.ListVendorAssertionsForCVE(context.Background(), "CVE-1")
	if err != nil || len(out) != 1 {
		t.Fatalf("ListVendorAssertionsForCVE() = %v, %v", out, err)
	}
}
