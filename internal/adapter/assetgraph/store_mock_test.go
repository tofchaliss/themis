//go:build integration

package assetgraph

import (
	"context"
	"errors"
	"testing"
	"time"

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
		case *bool:
			if i == 0 && m.val != nil {
				*x = m.val.(bool)
			}
		case *string:
			if s, ok := m.val.(string); ok && i == 0 {
				*x = s
			} else {
				*x = "id-value"
			}
		case *[]byte:
			if b, ok := m.val.([]byte); ok {
				*x = b
			} else {
				*x = []byte(`{}`)
			}
		case *time.Time:
			*x = time.Now().UTC()
		}
	}
	return nil
}

type mockPool struct {
	execErr   error
	queryErr  error
	queryRows pgx.Rows
	row       mockRow
	rows      []mockRow
	rowIdx    int
}

func (m *mockPool) nextRow() mockRow {
	if len(m.rows) == 0 {
		return m.row
	}
	if m.rowIdx >= len(m.rows) {
		return m.rows[len(m.rows)-1]
	}
	r := m.rows[m.rowIdx]
	m.rowIdx++
	return r
}

func (m *mockPool) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	if m.execErr != nil {
		return pgconn.CommandTag{}, m.execErr
	}
	return pgconn.NewCommandTag("INSERT 1"), nil
}

func (m *mockPool) QueryRow(context.Context, string, ...any) pgx.Row {
	return m.nextRow()
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
		if s, ok := d.(*string); ok {
			*s = row[i]
		}
	}
	return nil
}
func (m *mockRows) Values() ([]any, error) { return nil, nil }
func (m *mockRows) RawValues() [][]byte      { return nil }

func (m *mockPool) Query(context.Context, string, ...any) (pgx.Rows, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	if m.queryRows != nil {
		return m.queryRows, nil
	}
	return &mockRows{data: [][]string{{"cust-1"}}}, nil
}

func TestCreateMicroserviceProductLookupError(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: errors.New("db down")}})
	_, err := store.CreateMicroservice(context.Background(), domain.Microservice{ProductID: "p1", Name: "svc"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateMicroserviceInsertError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: true},
			{err: errors.New("insert failed")},
		},
	})
	_, err := store.CreateMicroservice(context.Background(), domain.Microservice{ProductID: "p1", Name: "svc"})
	if err == nil {
		t.Fatal("expected insert error")
	}
}

func TestEnsureEdgeError(t *testing.T) {
	store := NewPostgresStore(&mockPool{execErr: errors.New("edge failed")})
	if err := store.ensureEdge(context.Background(), "a", "b", domain.GraphEdgeTypeProductMicroservice); err == nil {
		t.Fatal("expected edge error")
	}
}

func TestGetMicroserviceNotFound(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: pgx.ErrNoRows}})
	_, err := store.GetMicroservice(context.Background(), "missing")
	if !errors.Is(err, ErrMicroserviceNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetCustomerNotFound(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: pgx.ErrNoRows}})
	_, err := store.GetCustomer(context.Background(), "missing")
	if !errors.Is(err, ErrCustomerNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateMicroserviceSuccessMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: true},
			{},
			{val: "product-node"},
			{val: "ms-node"},
		},
	})
	ms, err := store.CreateMicroservice(context.Background(), domain.Microservice{
		ProductID: "prod-1",
		Name:      "api",
		TechStack: map[string]string{"lang": "go"},
	})
	if err != nil {
		t.Fatalf("CreateMicroservice() error = %v", err)
	}
	if ms.ID == "" || ms.Name != "api" {
		t.Fatalf("ms = %+v", ms)
	}
}

func TestCreateCustomerSuccessMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{},
			{val: "customer-node"},
		},
	})
	customer, err := store.CreateCustomer(context.Background(), domain.Customer{
		Name:                    "team",
		ContactEmail:            "team@example.com",
		NotificationPreferences: map[string]string{"email": "true"},
	})
	if err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}
	if customer.ID == "" {
		t.Fatal("expected customer id")
	}
}

func TestCreateDeploymentSuccessMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{}, // GetMicroservice
			{}, // GetCustomer
			{}, // insert deployment created_at
			{val: "ms-node"},
			{val: "dep-node"},
			{val: "customer-node"},
		},
	})
	dep, err := store.CreateDeployment(context.Background(), domain.Deployment{
		MicroserviceID: "ms-1",
		CustomerID:     "cust-1",
		Environment:    "prod",
		Region:         "us-east-1",
	})
	if err != nil {
		t.Fatalf("CreateDeployment() error = %v", err)
	}
	if dep.ID == "" || dep.Environment != "prod" {
		t.Fatalf("dep = %+v", dep)
	}
}

func TestGetMicroserviceSuccessMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{}})
	ms, err := store.GetMicroservice(context.Background(), "ms-1")
	if err != nil {
		t.Fatalf("GetMicroservice() error = %v", err)
	}
	if ms.TechStack == nil {
		t.Fatal("expected tech stack map")
	}
}

func TestGetCustomerSuccessMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{}})
	customer, err := store.GetCustomer(context.Background(), "cust-1")
	if err != nil {
		t.Fatalf("GetCustomer() error = %v", err)
	}
	if customer.NotificationPreferences == nil {
		t.Fatal("expected notification preferences map")
	}
}

func TestSyncFindingGraphNodeIDError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: "node-cve"},
			{val: "node-pkg"},
			{val: "node-prod"},
			{err: errors.New("missing node")},
		},
	})
	err := store.syncFindingGraph(context.Background(), domain.EnrichmentFinding{
		VulnerabilityID: "v1", ProductID: "p1", ComponentID: "c1",
	})
	if err == nil {
		t.Fatal("expected nodeID error")
	}
}

func TestSyncFindingGraphEnsureEdgeError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: "node-cve"},
			{val: "node-pkg"},
			{val: "node-prod"},
			{val: "node-cve"},
			{val: "node-pkg"},
			{val: "node-prod"},
		},
		execErr: errors.New("edge failed"),
	})
	err := store.syncFindingGraph(context.Background(), domain.EnrichmentFinding{
		VulnerabilityID: "v1", ProductID: "p1", ComponentID: "c1",
	})
	if err == nil {
		t.Fatal("expected ensureEdge error")
	}
}

func TestComputeBlastRadiusSyncError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: false},
			{err: errors.New("sync failed")},
		},
	})
	_, err := store.ComputeBlastRadius(context.Background(), domain.EnrichmentFinding{
		VulnerabilityID: "v1", ProductID: "p1", ComponentID: "c1", SBOMDocumentID: "sbom-1",
	})
	if err == nil {
		t.Fatal("expected sync error")
	}
}

func TestComputeBlastRadiusDeletedSBOM(t *testing.T) {
	store := NewPostgresStore(&mockPool{rows: []mockRow{{val: true}}})
	result, err := store.ComputeBlastRadius(context.Background(), domain.EnrichmentFinding{
		VulnerabilityID: "vuln-1",
		ProductID:       "prod-1",
		ComponentID:     "comp-1",
		SBOMDocumentID:  "sbom-1",
	})
	if err != nil || result.Score != 1.0 {
		t.Fatalf("ComputeBlastRadius() = %+v, %v", result, err)
	}
}

func TestSbomActiveEmptyID(t *testing.T) {
	store := NewPostgresStore(&mockPool{})
	active, err := store.sbomActive(context.Background(), "")
	if err != nil || !active {
		t.Fatalf("sbomActive() = %v, %v", active, err)
	}
}

func TestSbomActiveLookupError(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: errors.New("db down")}})
	_, err := store.sbomActive(context.Background(), "sbom-1")
	if err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestSyncFindingGraphEnsureNodeError(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: errors.New("node failed")}})
	err := store.syncFindingGraph(context.Background(), domain.EnrichmentFinding{
		VulnerabilityID: "v1", ProductID: "p1", ComponentID: "c1",
	})
	if err == nil {
		t.Fatal("expected sync error")
	}
}

func TestProductBlastRadiusQueryError(t *testing.T) {
	store := NewPostgresStore(&mockPool{queryErr: errors.New("query failed")})
	_, err := store.ProductBlastRadius(context.Background(), "prod-1", "", "")
	if err == nil {
		t.Fatal("expected query error")
	}
}

func TestCustomersFromProductRowsError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		queryRows: &mockRows{data: [][]string{{"cust-1"}}, err: errors.New("rows err")},
	})
	_, err := store.customersFromProduct(context.Background(), "prod-1")
	if err == nil {
		t.Fatal("expected rows error")
	}
}

func TestComputeBlastRadiusFullMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: false},    // sbomActive deleted_at IS NOT NULL -> false
			{val: "node-cve"},
			{val: "node-pkg"},
			{val: "node-prod"},
			{val: "node-cve"},
			{val: "node-pkg"},
			{val: "node-prod"},
		},
	})
	result, err := store.ComputeBlastRadius(context.Background(), domain.EnrichmentFinding{
		VulnerabilityID: "vuln-1",
		ProductID:       "prod-1",
		ComponentID:     "comp-1",
		SBOMDocumentID:  "sbom-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 1.0 || len(result.CustomerIDs) != 1 {
		t.Fatalf("ComputeBlastRadius() = %+v", result)
	}
}

func TestProductBlastRadiusWithCustomers(t *testing.T) {
	store := NewPostgresStore(&mockPool{})
	result, err := store.ProductBlastRadius(context.Background(), "prod-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 1.0 || len(result.CustomerIDs) != 1 {
		t.Fatalf("ProductBlastRadius() = %+v", result)
	}
}

func TestBlastRadiusBaseline(t *testing.T) {
	store := NewPostgresStore(&mockPool{})
	result, err := store.ComputeBlastRadius(context.Background(), domain.EnrichmentFinding{})
	if err != nil || result.Score != domain.RiskScoreBlastRadiusMin {
		t.Fatalf("ComputeBlastRadius() = %+v, %v", result, err)
	}
}

func TestCreateCustomerDuplicateMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: &pgconn.PgError{Code: "23505"}}})
	_, err := store.CreateCustomer(context.Background(), domain.Customer{Name: "a", ContactEmail: "a@example.com"})
	if !errors.Is(err, ErrDuplicateCustomer) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateMicroserviceDuplicateMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: true},
			{err: &pgconn.PgError{Code: "23505"}},
		},
	})
	_, err := store.CreateMicroservice(context.Background(), domain.Microservice{ProductID: "p1", Name: "svc"})
	if !errors.Is(err, ErrDuplicateMicroservice) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateDeploymentDuplicateMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{},
			{},
			{err: &pgconn.PgError{Code: "23505"}},
		},
	})
	_, err := store.CreateDeployment(context.Background(), domain.Deployment{
		MicroserviceID: "ms-1",
		CustomerID:     "cust-1",
		Environment:    "prod",
	})
	if !errors.Is(err, ErrDuplicateDeployment) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureNodeErrorMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: errors.New("node failed")}})
	if _, err := store.ensureNode(context.Background(), domain.GraphNodeTypeProduct, "p1"); err == nil {
		t.Fatal("expected ensure node error")
	}
}

func TestGetMicroserviceDBError(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: errors.New("db error")}})
	_, err := store.GetMicroservice(context.Background(), "ms-1")
	if err == nil || errors.Is(err, ErrMicroserviceNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetCustomerDBError(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: errors.New("db error")}})
	_, err := store.GetCustomer(context.Background(), "cust-1")
	if err == nil || errors.Is(err, ErrCustomerNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateDeploymentMicroserviceMissingMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: pgx.ErrNoRows}})
	_, err := store.CreateDeployment(context.Background(), domain.Deployment{
		MicroserviceID: "missing",
		CustomerID:     "cust-1",
		Environment:    "prod",
	})
	if !errors.Is(err, ErrMicroserviceNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateDeploymentCustomerMissingMock(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{},
			{err: pgx.ErrNoRows},
		},
	})
	_, err := store.CreateDeployment(context.Background(), domain.Deployment{
		MicroserviceID: "ms-1",
		CustomerID:     "missing",
		Environment:    "prod",
	})
	if !errors.Is(err, ErrCustomerNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestNodeIDDBError(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: errors.New("lookup failed")}})
	_, err := store.nodeID(context.Background(), domain.GraphNodeTypeCustomer, "cust-1")
	if err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestCreateMicroserviceEnsureNodeError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: true},
			{},
			{err: errors.New("node insert failed")},
		},
	})
	_, err := store.CreateMicroservice(context.Background(), domain.Microservice{ProductID: "p1", Name: "svc"})
	if err == nil {
		t.Fatal("expected ensure node error")
	}
}

func TestCreateMicroserviceEnsureEdgeError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{val: true},
			{},
			{val: "product-node"},
			{val: "ms-node"},
		},
		execErr: errors.New("edge failed"),
	})
	_, err := store.CreateMicroservice(context.Background(), domain.Microservice{ProductID: "p1", Name: "svc"})
	if err == nil {
		t.Fatal("expected ensure edge error")
	}
}

func TestCreateCustomerEnsureNodeError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{
			{},
			{err: errors.New("node failed")},
		},
	})
	_, err := store.CreateCustomer(context.Background(), domain.Customer{Name: "team", ContactEmail: "team@example.com"})
	if err == nil {
		t.Fatal("expected ensure node error")
	}
}

func TestGetMicroserviceEmptyTechStack(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{val: []byte(nil)}})
	ms, err := store.GetMicroservice(context.Background(), "ms-1")
	if err != nil {
		t.Fatal(err)
	}
	if ms.TechStack == nil || len(ms.TechStack) != 0 {
		t.Fatalf("tech stack = %#v", ms.TechStack)
	}
}

func TestCreateMicroserviceProductMissing(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{val: false}})
	_, err := store.CreateMicroservice(context.Background(), domain.Microservice{ProductID: "p1", Name: "svc"})
	if !errors.Is(err, ErrProductNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestNodeIDMissing(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: pgx.ErrNoRows}})
	_, err := store.nodeID(context.Background(), domain.GraphNodeTypeCustomer, "missing")
	if err == nil {
		t.Fatal("expected node id error")
	}
}

func TestIsUniqueViolationHelper(t *testing.T) {
	if isUniqueViolation(errors.New("plain")) {
		t.Fatal("expected false")
	}
	pgErr := &pgconn.PgError{Code: "23505"}
	if !isUniqueViolation(pgErr) {
		t.Fatal("expected unique violation")
	}
}

func TestCreateCustomerInsertError(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: errors.New("insert failed")}})
	_, err := store.CreateCustomer(context.Background(), domain.Customer{Name: "team", ContactEmail: "team@example.com"})
	if err == nil {
		t.Fatal("expected insert error")
	}
}

func TestCreateDeploymentInsertError(t *testing.T) {
	store := NewPostgresStore(&mockPool{
		rows: []mockRow{{}, {}, {err: errors.New("insert failed")}},
	})
	_, err := store.CreateDeployment(context.Background(), domain.Deployment{
		MicroserviceID: "ms-1", CustomerID: "cust-1", Environment: "prod",
	})
	if err == nil {
		t.Fatal("expected insert error")
	}
}
