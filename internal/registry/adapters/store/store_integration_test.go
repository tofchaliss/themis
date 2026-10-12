//go:build integration

package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/domain"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "registry-store-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15533).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"shared_buffers": "128kB", "max_connections": "10"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping registry store integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15533/themis?sslmode=disable"
	if err := migrateUp(testDSN); err != nil {
		_ = db.Stop()
		panic(err)
	}
	code := m.Run()
	_ = db.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func migrationsDir() string {
	path, _ := filepath.Abs("migrations")
	return "file://" + path
}

// registryMigrationsTable is Registry's OWN golang-migrate bookkeeping table, mirroring
// cmd/registry: Registry co-locates its identity tables in the `evidence` database, so sharing
// golang-migrate's default `schema_migrations` with Evidence made whichever migrated second
// read the other's version and skip its own CREATE TABLEs. The tests migrate through the same
// configuration the node uses, so a test that reads this row reads the row an operator reads.
const registryMigrationsTable = "registry_schema_migrations"

// migrationDSN attaches the migrations-table parameter to dsn. It MUST stay a separate string
// from the pool DSN: pgx forwards an unknown parameter to Postgres as a startup option and
// every runtime connection would fail with `unrecognized configuration parameter`.
func migrationDSN(dsn string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("x-migrations-table", registryMigrationsTable)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func newMigrate(dsn string) (*migrate.Migrate, error) {
	mdsn, err := migrationDSN(dsn)
	if err != nil {
		return nil, err
	}
	return migrate.New(migrationsDir(), mdsn)
}

func migrateUp(dsn string) error {
	m, err := newMigrate(dsn)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testDSN == "" {
		t.Skip("no database")
	}
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	return registerPool(t, pool)
}

// newBoundedPool caps the pool's connections. The embedded server runs with a small
// max_connections, so a test that fires more callers than that would fail on connection
// exhaustion — which reads like the upsert erroring. Callers above the cap queue on the pool
// (bounded by their context) and still contend for real.
func newBoundedPool(t *testing.T, maxConns int32) *pgxpool.Pool {
	t.Helper()
	if testDSN == "" {
		t.Skip("no database")
	}
	cfg, err := pgxpool.ParseConfig(testDSN)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	return registerPool(t, pool)
}

func registerPool(t *testing.T, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	truncate(t, pool)
	t.Cleanup(func() {
		truncate(t, pool)
		pool.Close()
	})
	return pool
}

func truncate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), "TRUNCATE deployments, microservices, customers, releases, projects, products RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// seed inserts a Product → Project → Release chain and returns their ids.
func seed(t *testing.T, s *store.Store) (domain.ProductID, domain.ProjectID, domain.ReleaseID) {
	t.Helper()
	ctx := context.Background()
	prod, _ := domain.NewProduct("prod-1", "Themis")
	if err := s.SaveProduct(ctx, prod); err != nil {
		t.Fatalf("save product: %v", err)
	}
	proj, _ := domain.NewProject("proj-1", "prod-1", "api")
	if err := s.SaveProject(ctx, proj); err != nil {
		t.Fatalf("save project: %v", err)
	}
	rel, _ := domain.NewRelease("rel-1", "proj-1", "1.2.3")
	if err := s.SaveRelease(ctx, rel); err != nil {
		t.Fatalf("save release: %v", err)
	}
	return prod.ID(), proj.ID(), rel.ID()
}

func TestRegisterAndLookup(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	_, projID, relID := seed(t, s)

	got, err := s.GetRelease(ctx, relID)
	if err != nil {
		t.Fatalf("get release: %v", err)
	}
	if got.ID() != relID || got.ProjectID() != projID || got.Version() != "1.2.3" {
		t.Errorf("release = %+v", got)
	}

	list, err := s.ListReleases(ctx, projID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID() != relID {
		t.Errorf("list = %+v", list)
	}
}

func TestBlastRadius(t *testing.T) {
	ctx := context.Background()
	s := store.New(newPool(t))
	_, _, rel := seed(t, s) // prod-1 → proj-1 → rel-1

	// Unpopulated estate → 0; unknown release → 0.
	if n, err := s.BlastRadiusCustomers(ctx, string(rel)); err != nil || n != 0 {
		t.Fatalf("empty blast = %d, %v, want 0", n, err)
	}
	if n, _ := s.BlastRadiusCustomers(ctx, "nope"); n != 0 {
		t.Errorf("unknown release blast = %d, want 0", n)
	}

	// One microservice on prod-1, one customer, one deployment → blast 1.
	ms, _ := domain.NewMicroservice("ms-1", "prod-1", "payments")
	must(t, s.SaveMicroservice(ctx, ms))
	c1, _ := domain.NewCustomer("cust-1", "Acme")
	must(t, s.SaveCustomer(ctx, c1))
	d1, _ := domain.NewDeployment("dep-1", "ms-1", "cust-1", "prod")
	must(t, s.SaveDeployment(ctx, d1))
	if n, err := s.BlastRadiusCustomers(ctx, string(rel)); err != nil || n != 1 {
		t.Errorf("blast = %d, %v, want 1", n, err)
	}

	// A second customer + deployment → 2 distinct customers.
	c2, _ := domain.NewCustomer("cust-2", "Globex")
	must(t, s.SaveCustomer(ctx, c2))
	d2, _ := domain.NewDeployment("dep-2", "ms-1", "cust-2", "prod")
	must(t, s.SaveDeployment(ctx, d2))
	if n, _ := s.BlastRadiusCustomers(ctx, string(rel)); n != 2 {
		t.Errorf("blast after 2nd customer = %d, want 2", n)
	}

	// A duplicate deployment to cust-1 (different env) does NOT double-count (DISTINCT).
	d3, _ := domain.NewDeployment("dep-3", "ms-1", "cust-1", "staging")
	must(t, s.SaveDeployment(ctx, d3))
	if n, _ := s.BlastRadiusCustomers(ctx, string(rel)); n != 2 {
		t.Errorf("blast after duplicate customer = %d, want 2 (DISTINCT)", n)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestExists(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	prodID, projID, relID := seed(t, s)

	for _, tc := range []struct {
		name  string
		check func() (bool, error)
		want  bool
	}{
		{"product yes", func() (bool, error) { return s.ProductExists(ctx, string(prodID)) }, true},
		{"product no", func() (bool, error) { return s.ProductExists(ctx, "nope") }, false},
		{"project yes", func() (bool, error) { return s.ProjectExists(ctx, string(projID)) }, true},
		{"project no", func() (bool, error) { return s.ProjectExists(ctx, "nope") }, false},
		{"release yes", func() (bool, error) { return s.ReleaseExists(ctx, string(relID)) }, true},
		{"release no", func() (bool, error) { return s.ReleaseExists(ctx, "nope") }, false},
	} {
		got, err := tc.check()
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGetRelease_NotFound(t *testing.T) {
	pool := newPool(t)
	s := store.New(pool)
	if _, err := s.GetRelease(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetRelease(missing) = %v, want ErrNotFound", err)
	}
}

func TestForeignKeysEnforceMembership(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	// Project referencing a non-existent Product → FK violation.
	orphanProj, _ := domain.NewProject("proj-x", "no-such-product", "api")
	if err := s.SaveProject(ctx, orphanProj); err == nil {
		t.Error("SaveProject with unknown product: expected FK error")
	}
	// Release referencing a non-existent Project → FK violation.
	orphanRel, _ := domain.NewRelease("rel-x", "no-such-project", "1.0")
	if err := s.SaveRelease(ctx, orphanRel); err == nil {
		t.Error("SaveRelease with unknown project: expected FK error")
	}
	// Duplicate product id → PK violation.
	prod, _ := domain.NewProduct("dup", "A")
	if err := s.SaveProduct(ctx, prod); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveProduct(ctx, prod); err == nil {
		t.Error("duplicate product: expected PK error")
	}
}

func TestReadPaths_MalformedRow(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	// Insert a release with an empty version directly, bypassing the domain, so the
	// read paths hit their reconstruction (NewRelease) error branch.
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ('p','A')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, product_id, name) VALUES ('j','p','api')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO releases (id, project_id, version) VALUES ('bad','j','')`); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetRelease(ctx, "bad"); err == nil {
		t.Error("GetRelease with empty version: want reconstruction error")
	}
	if _, err := s.ListReleases(ctx, "j"); err == nil {
		t.Error("ListReleases with empty version: want reconstruction error")
	}
}

func TestPurge(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	seed(t, s)

	if err := s.Purge(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM products").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("products after purge = %d, want 0", n)
	}
}

func TestMigration_DownUp(t *testing.T) {
	if testDSN == "" {
		t.Skip("no database")
	}
	m, err := newMigrate(testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("down: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("up: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), "SELECT 1 FROM releases LIMIT 0"); err != nil {
		t.Fatalf("releases table missing after down/up: %v", err)
	}
}

// DASH-1: the product → project → release traversal, with exact-name lookup at each level.
//
// Exact match, not a prefix: the caller is a human or a GUI who KNOWS the product they mean, and a
// fuzzy match returns a set they then have to disambiguate — which is the problem this exists to
// remove, not a smaller version of it.
func TestListProductsAndProjects(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	prodID, _, _ := seed(t, s)

	// A second product + project, so a filter has something to exclude.
	other, _ := domain.NewProduct("prod-2", "Other")
	if err := s.SaveProduct(ctx, other); err != nil {
		t.Fatalf("save other product: %v", err)
	}
	proj2, _ := domain.NewProject("proj-2", prodID, "worker")
	if err := s.SaveProject(ctx, proj2); err != nil {
		t.Fatalf("save second project: %v", err)
	}

	all, err := s.ListProducts(ctx, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("ListProducts(all) = %d, %v; want 2", len(all), err)
	}
	one, err := s.ListProducts(ctx, "Themis")
	if err != nil || len(one) != 1 || one[0].Name() != "Themis" {
		t.Fatalf("ListProducts(Themis) = %+v, %v", one, err)
	}
	if none, err := s.ListProducts(ctx, "Them"); err != nil || len(none) != 0 {
		t.Errorf("a PREFIX must not match — the lookup is exact: %+v, %v", none, err)
	}

	projs, err := s.ListProjects(ctx, prodID, "")
	if err != nil || len(projs) != 2 {
		t.Fatalf("ListProjects = %d, %v; want 2", len(projs), err)
	}
	named, err := s.ListProjects(ctx, prodID, "api")
	if err != nil || len(named) != 1 || named[0].Name() != "api" {
		t.Fatalf("ListProjects(api) = %+v, %v", named, err)
	}
	// Scoped to the product: a project of another product must never leak in.
	if leaked, err := s.ListProjects(ctx, "prod-2", ""); err != nil || len(leaked) != 0 {
		t.Errorf("projects leaked across products: %+v, %v", leaked, err)
	}
}

// GetProduct and GetProject are the two reads the DASH-1 name traversal rests on
// (GET /products → /products/{id}/projects → /projects/{id}/releases). Both were entirely
// uncovered, which is part of why this package sat under its threshold (DEV-COV-1).
func TestGetProductAndProject(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	prodID, projID, _ := seed(t, s)

	prod, err := s.GetProduct(ctx, prodID)
	if err != nil {
		t.Fatalf("get product: %v", err)
	}
	if prod.ID() != prodID || prod.Name() != "Themis" {
		t.Errorf("product = %+v, want id=%s name=Themis", prod, prodID)
	}

	proj, err := s.GetProject(ctx, projID)
	if err != nil {
		t.Fatalf("get project: %v", err)
	}
	if proj.ID() != projID || proj.ProductID() != prodID || proj.Name() != "api" {
		t.Errorf("project = %+v, want id=%s product=%s name=api", proj, projID, prodID)
	}

	// A missing row must be ErrNotFound, never a zero value: the traversal has to tell
	// "no such product" from "a product whose name is empty", and a caller that cannot
	// distinguish them renders a blank page instead of a 404.
	if _, err := s.GetProduct(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetProduct(missing) = %v, want ErrNotFound", err)
	}
	if _, err := s.GetProject(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetProject(missing) = %v, want ErrNotFound", err)
	}
}

// --- find-or-create (EDR-INTAKE-01 B4, tasks 1.3–1.6) ----------------------

// Task 1.3. The conflict path is the whole point: a happy-path-only test would pass even with
// `ON CONFLICT (name)`, which does not infer the expression index at all (design §5, trap 1).
// And the id this process minted for the losing insert must never be the answer (trap 2) —
// which is also why the stored casing stays the FIRST caller's: nothing is renamed.
func TestUpsertProductReturnsExistingIDAndFirstCasing(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	first, created, err := s.UpsertProduct(ctx, "OAMP")
	if err != nil || !created || first == "" {
		t.Fatalf("first UpsertProduct = %q, created=%v, err=%v; want a new id and created=true", first, created, err)
	}

	again, created, err := s.UpsertProduct(ctx, "oamp")
	if err != nil {
		t.Fatalf("second UpsertProduct: %v", err)
	}
	if again != first {
		t.Errorf("second UpsertProduct id = %q, want the existing %q (the minted id is discarded)", again, first)
	}
	if created {
		t.Error("second UpsertProduct reported created=true; the row already existed")
	}
	if n := countRows(t, pool, `SELECT count(*) FROM products`); n != 1 {
		t.Errorf("products = %d, want 1 ('OAMP' and 'oamp' are one product)", n)
	}

	var name string
	if err := pool.QueryRow(ctx, `SELECT name FROM products WHERE id = $1`, first).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "OAMP" {
		t.Errorf("stored name = %q, want %q — the first caller's casing, never renamed", name, "OAMP")
	}
}

// Task 1.4. Project uniqueness is scoped to its Product, so the same name under two Products is
// two rows. A global unique index on lower(name) would collapse them and silently hand the
// second product the first one's project.
func TestUpsertProjectIsScopedToItsProduct(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	prodA, _, err := s.UpsertProduct(ctx, "A")
	must(t, err)
	prodB, _, err := s.UpsertProduct(ctx, "B")
	must(t, err)

	inA, createdA, err := s.UpsertProject(ctx, prodA, "core")
	if err != nil || !createdA {
		t.Fatalf("UpsertProject(A, core) = %q, created=%v, err=%v; want created=true", inA, createdA, err)
	}
	inB, createdB, err := s.UpsertProject(ctx, prodB, "core")
	if err != nil || !createdB {
		t.Fatalf("UpsertProject(B, core) = %q, created=%v, err=%v; want created=true", inB, createdB, err)
	}
	if inA == inB {
		t.Errorf("both products got project id %q; the same name under a different product is a different row", inA)
	}

	if n := countRows(t, pool, `SELECT count(*) FROM projects WHERE lower(name) = lower($1)`, "core"); n != 2 {
		t.Errorf("projects named core = %d, want 2", n)
	}
	for _, p := range []string{prodA, prodB} {
		if n := countRows(t, pool, `SELECT count(*) FROM projects WHERE product_id = $1 AND lower(name) = lower($2)`, p, "core"); n != 1 {
			t.Errorf("projects named core under %s = %d, want 1", p, n)
		}
	}
}

// Task 1.4. The conflict path at the project level, including the folded case.
func TestUpsertProjectReturnsExistingID(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	prod, _, err := s.UpsertProduct(ctx, "A")
	must(t, err)

	first, created, err := s.UpsertProject(ctx, prod, "Core")
	if err != nil || !created || first == "" {
		t.Fatalf("first UpsertProject = %q, created=%v, err=%v", first, created, err)
	}
	again, created, err := s.UpsertProject(ctx, prod, "core")
	if err != nil {
		t.Fatalf("second UpsertProject: %v", err)
	}
	if again != first || created {
		t.Errorf("second UpsertProject = %q, created=%v; want %q, created=false", again, created, first)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM projects WHERE product_id = $1`, prod); n != 1 {
		t.Errorf("projects under %s = %d, want 1", prod, n)
	}
}

// Task 1.5. A version is a machine build string whose case Themis does not own, so release
// uniqueness is EXACT: folding it would merge two builds, and a prefix is a different build
// again. This is the asymmetry B4 takes deliberately against the folded name levels above.
func TestUpsertReleaseIsExactOnVersion(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	prod, _, err := s.UpsertProduct(ctx, "A")
	must(t, err)
	proj, _, err := s.UpsertProject(ctx, prod, "core")
	must(t, err)

	versions := []string{"R1917.256", "r1917.256", "R1917.25"}
	ids := make(map[string]string, len(versions))
	for _, v := range versions {
		id, created, err := s.UpsertRelease(ctx, proj, v)
		if err != nil || !created || id == "" {
			t.Fatalf("UpsertRelease(%q) = %q, created=%v, err=%v; want a new row", v, id, created, err)
		}
		for prev, prevID := range ids {
			if prevID == id {
				t.Errorf("version %q reused %q's id %q; versions are compared exactly", v, prev, id)
			}
		}
		ids[v] = id
	}

	if n := countRows(t, pool,
		`SELECT count(*) FROM releases WHERE project_id = $1 AND version = ANY($2)`,
		proj, versions); n != len(versions) {
		t.Errorf("releases = %d, want %d (case- and prefix-distinct versions are distinct rows)", n, len(versions))
	}
}

// Task 1.5. The conflict path at the release level.
func TestUpsertReleaseReturnsExistingID(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	prod, _, err := s.UpsertProduct(ctx, "A")
	must(t, err)
	proj, _, err := s.UpsertProject(ctx, prod, "core")
	must(t, err)

	first, created, err := s.UpsertRelease(ctx, proj, "R1917.256")
	if err != nil || !created || first == "" {
		t.Fatalf("first UpsertRelease = %q, created=%v, err=%v", first, created, err)
	}
	again, created, err := s.UpsertRelease(ctx, proj, "R1917.256")
	if err != nil {
		t.Fatalf("second UpsertRelease: %v", err)
	}
	if again != first || created {
		t.Errorf("second UpsertRelease = %q, created=%v; want %q, created=false", again, created, first)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM releases WHERE project_id = $1`, proj); n != 1 {
		t.Errorf("releases under %s = %d, want 1", proj, n)
	}
}

// Task 1.6 — the property the constraints exist for, and the one a single-threaded test cannot
// see. Two bots building the same version at the same moment is the normal case: a
// SELECT-then-INSERT would fork a row here, which is exactly why uniqueness lives in the
// database and not in a check-then-insert (B4).
func TestUpsertConcurrentCallersConvergeOnOneRow(t *testing.T) {
	// Bounded by a test context so a regression fails instead of hanging the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := newBoundedPool(t, 6)
	s := store.New(pool)
	const callers = 25

	products := upsertConcurrently(ctx, callers, func(ctx context.Context) (string, bool, error) {
		return s.UpsertProduct(ctx, "OAMP")
	})
	productID := assertConverged(t, "product", products)
	if n := countRows(t, pool, `SELECT count(*) FROM products WHERE lower(name) = lower($1)`, "OAMP"); n != 1 {
		t.Errorf("products named OAMP = %d, want exactly 1", n)
	}

	projects := upsertConcurrently(ctx, callers, func(ctx context.Context) (string, bool, error) {
		return s.UpsertProject(ctx, productID, "core")
	})
	projectID := assertConverged(t, "project", projects)
	if n := countRows(t, pool,
		`SELECT count(*) FROM projects WHERE product_id = $1 AND lower(name) = lower($2)`,
		productID, "core"); n != 1 {
		t.Errorf("projects named core under the product = %d, want exactly 1", n)
	}

	releases := upsertConcurrently(ctx, callers, func(ctx context.Context) (string, bool, error) {
		return s.UpsertRelease(ctx, projectID, "R1917.256")
	})
	assertConverged(t, "release", releases)
	if n := countRows(t, pool,
		`SELECT count(*) FROM releases WHERE project_id = $1 AND version = $2`,
		projectID, "R1917.256"); n != 1 {
		t.Errorf("releases at R1917.256 under the project = %d, want exactly 1", n)
	}
}

// upsertResult is one caller's answer: the id it was given, whether it was the creator, and
// whether it failed at all.
type upsertResult struct {
	id      string
	created bool
	err     error
}

// upsertConcurrently releases n callers at the same instant and collects their answers. The
// shared start channel matters: goroutines started in a loop would otherwise serialize, and the
// race this test exists to cover would never be attempted.
func upsertConcurrently(ctx context.Context, n int, upsert func(context.Context) (string, bool, error)) []upsertResult {
	out := make([]upsertResult, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			id, created, err := upsert(ctx)
			out[i] = upsertResult{id: id, created: created, err: err}
		}(i)
	}
	close(start)
	wg.Wait()
	return out
}

// assertConverged asserts the find-or-create contract across concurrent callers — no errors,
// one id, exactly one creator — and returns the id they agreed on.
func assertConverged(t *testing.T, level string, results []upsertResult) string {
	t.Helper()
	var id string
	creators := 0
	for i, r := range results {
		if r.err != nil {
			t.Errorf("%s caller %d: %v — a losing caller must find the winner, not fail", level, i, r.err)
			continue
		}
		if r.id == "" {
			t.Errorf("%s caller %d returned an empty id", level, i)
			continue
		}
		if id == "" {
			id = r.id
		} else if r.id != id {
			t.Errorf("%s caller %d returned id %q; caller(s) before it returned %q — the callers forked", level, i, r.id, id)
		}
		if r.created {
			creators++
		}
	}
	if creators != 1 {
		t.Errorf("%s: %d callers reported created=true, want exactly 1", level, creators)
	}
	return id
}

// The estate-graph existence checks (C1). RegisterDeployment validates its microservice and
// customer through these before inserting, so a false negative here turns a valid deployment
// into a rejected one and a false positive defers the failure to the foreign key.
func TestEstateExists(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	seed(t, s) // prod-1, which the microservice FK requires

	ms, _ := domain.NewMicroservice("ms-1", "prod-1", "payments")
	must(t, s.SaveMicroservice(ctx, ms))
	cust, _ := domain.NewCustomer("cust-1", "Acme")
	must(t, s.SaveCustomer(ctx, cust))

	for _, tc := range []struct {
		name  string
		check func() (bool, error)
		want  bool
	}{
		{"microservice yes", func() (bool, error) { return s.MicroserviceExists(ctx, "ms-1") }, true},
		{"microservice no", func() (bool, error) { return s.MicroserviceExists(ctx, "nope") }, false},
		{"customer yes", func() (bool, error) { return s.CustomerExists(ctx, "cust-1") }, true},
		{"customer no", func() (bool, error) { return s.CustomerExists(ctx, "nope") }, false},
	} {
		got, err := tc.check()
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
