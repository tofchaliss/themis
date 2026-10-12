//go:build integration

// Migration 000003 — Registry uniqueness at the database (EDR-INTAKE-01 amendment B4).
//
// Four properties, and the first one is the one a single-threaded test cannot see: a Registry
// write that arrives while the migration holds its lock WAITS and then proceeds. The others are
// that the pre-flight refuses by name instead of repairing, that the indexes are enforced at
// each level, and that the down migration really drops them.
//
// These tests move the schema between versions 2 and 3, because version 2 is the only shape in
// which a duplicate can be seeded at all. Every one of them restores version 3 afterwards
// through golang-migrate, which is also what proves the driver executes the file's explicit
// BEGIN/COMMIT as written.
//
// The embedded-Postgres harness lives in store_integration_test.go (TestMain, testDSN, newPool,
// truncate) and so does the migrator seam (newMigrate, registryMigrationsTable), which carries
// Registry's OWN bookkeeping table exactly as cmd/registry does — these tests migrate through
// the node's configuration, not a second one.

package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// uniquenessVersion is migration 000003; preUniquenessVersion is the schema without it.
	uniquenessVersion    = 3
	preUniquenessVersion = 2

	uniqueViolationCode = "23505"

	productsNameIndex    = "registry_products_name_key"
	projectsNameIndex    = "registry_projects_product_name_key"
	releasesVersionIndex = "registry_releases_project_version_key"

	insertProductSQL = `INSERT INTO products (id, name) VALUES ($1, $2)`
	insertProjectSQL = `INSERT INTO projects (id, product_id, name) VALUES ($1, $2, $3)`
	insertReleaseSQL = `INSERT INTO releases (id, project_id, version) VALUES ($1, $2, $3)`
)

// uniquenessSQL reads one half of the 000003 pair, so the tests exercise the shipped file and
// not a copy of it that can drift.
func uniquenessSQL(t *testing.T, direction string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("migrations", "000003_registry_uniqueness."+direction+".sql"))
	if err != nil {
		t.Fatalf("read 000003 %s: %v", direction, err)
	}
	return string(b)
}

// splitUniquenessUp cuts the up migration where the pre-flight ends and the index builds begin,
// so a test can stop where the migration holds the lock and nothing else.
func splitUniquenessUp(t *testing.T) (preflight, indexes string) {
	t.Helper()
	up := uniquenessSQL(t, "up")
	cut := strings.Index(up, "CREATE UNIQUE INDEX")
	if cut < 0 {
		t.Fatal("the up migration builds no unique index")
	}
	return up[:cut], up[cut:]
}

// newMigrator builds a migrator over Registry's own bookkeeping table (newMigrate), so Force
// and Migrate here move the same version row cmd/registry moves and INSTALLATION.md names.
func newMigrator(t *testing.T) *migrate.Migrate {
	t.Helper()
	if testDSN == "" {
		t.Skip("no database")
	}
	m, err := newMigrate(testDSN)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return m
}

// migrateToErr moves the schema to version v and RETURNS the outcome — the refusal tests assert
// on it, so it must not be swallowed by a Fatalf.
func migrateToErr(t *testing.T, v uint) error {
	t.Helper()
	m := newMigrator(t)
	defer m.Close()
	if err := m.Migrate(v); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func migrateTo(t *testing.T, v uint) {
	t.Helper()
	if err := migrateToErr(t, v); err != nil {
		t.Fatalf("migrate to %d: %v", v, err)
	}
}

// withoutUniquenessIndexes takes the schema back to version 2 for the duration of the test and
// restores version 3 afterwards, from whatever state the test left behind: the tables are
// emptied first (a refusal test deliberately leaves duplicates, which the pre-flight would
// refuse again), the indexes dropped, and the version forced back to 2 — which also clears the
// `dirty` flag golang-migrate sets when the pre-flight raises.
func withoutUniquenessIndexes(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	t.Cleanup(func() {
		truncate(t, pool)
		if _, err := pool.Exec(context.Background(), uniquenessSQL(t, "down")); err != nil {
			t.Fatalf("restore: drop indexes: %v", err)
		}
		m := newMigrator(t)
		defer m.Close()
		if err := m.Force(preUniquenessVersion); err != nil {
			t.Fatalf("restore: force %d: %v", preUniquenessVersion, err)
		}
		if err := m.Migrate(uniquenessVersion); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			t.Fatalf("restore: migrate to %d: %v", uniquenessVersion, err)
		}
	})
	migrateTo(t, preUniquenessVersion)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %s %v: %v", sql, args, err)
	}
}

// assertUniqueViolation requires a 23505 that NAMES the expected index. The code alone is not
// the assertion: a violation attributed to the wrong index would mean the constraint that
// actually fired is not the one the migration was asked for.
func assertUniqueViolation(t *testing.T, err error, index string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a unique violation on %s, the insert succeeded", index)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected a Postgres error on %s, got %v", index, err)
	}
	if pgErr.Code != uniqueViolationCode {
		t.Fatalf("expected %s on %s, got %s (%v)", uniqueViolationCode, index, pgErr.Code, err)
	}
	if pgErr.ConstraintName != index {
		t.Fatalf("the violation names %q, want %q", pgErr.ConstraintName, index)
	}
}

func indexExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var exists bool
	const q = `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relkind = 'i' AND relname = $1)`
	if err := pool.QueryRow(context.Background(), q, name).Scan(&exists); err != nil {
		t.Fatalf("index lookup %s: %v", name, err)
	}
	return exists
}

func countRows(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// idSnapshot renders the registry's rows — per table, the count and every id in order — so
// "counts and ids unchanged" is a comparison a failure can print.
func idSnapshot(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var out strings.Builder
	for _, q := range []struct{ table, sql string }{
		{"products", `SELECT id FROM products ORDER BY id`},
		{"projects", `SELECT id FROM projects ORDER BY id`},
		{"releases", `SELECT id FROM releases ORDER BY id`},
	} {
		rows, err := pool.Query(context.Background(), q.sql)
		if err != nil {
			t.Fatalf("snapshot %s: %v", q.table, err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("snapshot %s: %v", q.table, err)
		}
		fmt.Fprintf(&out, "%s(%d)=%v\n", q.table, len(ids), ids)
	}
	return out.String()
}

// TestUniquenessMigrationWriterWaitsThenSucceeds is the revision-2 lock property: writes are
// quiesced from the pre-flight through the last index build, and a Registry write that arrives
// meanwhile WAITS and then proceeds rather than failing. One context bounds the whole sequence,
// including the cleanup, so a regression that reintroduces an unbounded wait fails the test
// instead of hanging the suite.
func TestUniquenessMigrationWriterWaitsThenSucceeds(t *testing.T) {
	pool := newPool(t)
	withoutUniquenessIndexes(t, pool)
	preflight, indexes := splitUniquenessUp(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A is the migration: the file's statements up to and including the pre-flight, inside
	// its still-open transaction, holding SHARE ROW EXCLUSIVE on all three tables.
	connA, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("connect A: %v", err)
	}
	defer func() { _ = connA.Close(context.Background()) }()
	if _, err := connA.Exec(ctx, preflight); err != nil {
		t.Fatalf("pre-flight: %v", err)
	}

	// B is an ordinary Registry write arriving mid-migration. It is NOT a duplicate, and it
	// sets no lock_timeout: waiting is the designed outcome, not an error to be shortened.
	connB, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("connect B: %v", err)
	}
	defer func() { _ = connB.Close(context.Background()) }()

	const writerID = "prod-writer-waits"
	done := make(chan error, 1)
	go func() {
		_, err := connB.Exec(ctx, insertProductSQL, writerID, "writer-waits")
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("the insert completed while the migration held the lock (err=%v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	waitForLockWait(ctx, t, pool, connB.PgConn().PID())

	// The migration finishes: three index builds, then COMMIT releases the lock.
	if _, err := connA.Exec(ctx, indexes); err != nil {
		t.Fatalf("index builds: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the waiting insert failed instead of proceeding: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting insert did not complete after the migration committed")
	}
	if n := countRows(t, pool, `SELECT count(*) FROM products WHERE id = $1`, writerID); n != 1 {
		t.Fatalf("the waiting writer's row is not present (count=%d)", n)
	}
}

// waitForLockWait asserts the backend is blocked on one of the three locked relations, which is
// what makes "it has not completed yet" a statement about the lock and not about scheduling.
func waitForLockWait(ctx context.Context, t *testing.T, pool *pgxpool.Pool, pid uint32) {
	t.Helper()
	const q = `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
	            WHERE l.pid = $1 AND NOT l.granted
	              AND c.relname IN ('products', 'projects', 'releases')`
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, q, int32(pid)).Scan(&waiting); err != nil {
			t.Fatalf("pg_locks: %v", err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pg_locks never showed backend %d waiting on products/projects/releases", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestUniquenessMigrationRefusesCaseInsensitiveDuplicateProducts: "OAMP" and "oamp" are one
// product (B4 folds case on human-typed labels), so migrate-up must refuse — naming BOTH ids,
// because an operator cannot resolve a duplicate the message does not identify.
func TestUniquenessMigrationRefusesCaseInsensitiveDuplicateProducts(t *testing.T) {
	pool := newPool(t)
	withoutUniquenessIndexes(t, pool)

	mustExec(t, pool, insertProductSQL, "prod-oamp-upper", "OAMP")
	mustExec(t, pool, insertProductSQL, "prod-oamp-lower", "oamp")

	err := migrateToErr(t, uniquenessVersion)
	if err == nil {
		t.Fatal("migrate-up succeeded over a case-insensitive duplicate product")
	}
	for _, want := range []string{"products", "oamp", "rows=2", "prod-oamp-upper", "prod-oamp-lower"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not name %q:\n%v", want, err)
		}
	}

	// It refuses; it never repairs (B4). Both rows are still there, with their own casing.
	if n := countRows(t, pool, `SELECT count(*) FROM products`); n != 2 {
		t.Fatalf("the refused migration changed the data: %d products, want 2", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM products WHERE name IN ('OAMP', 'oamp')`); n != 2 {
		t.Fatalf("the refused migration rewrote a name: %d of the seeded casings survive, want 2", n)
	}
	if indexExists(t, pool, productsNameIndex) {
		t.Fatalf("%s was created although the pre-flight refused", productsNameIndex)
	}

	// golang-migrate marks the version row BEFORE running the file, so a refusal leaves the
	// version dirty and a restart will not retry it. That is why the up migration's header and
	// INSTALLATION.md section 8 tell an operator to force the version back to 2 — asserted
	// here, on the table the node actually keeps (registry_schema_migrations), so the
	// documented recovery cannot quietly stop being the right one.
	var version int
	var dirty bool
	q := `SELECT version, dirty FROM ` + registryMigrationsTable
	if err := pool.QueryRow(context.Background(), q).Scan(&version, &dirty); err != nil {
		t.Fatalf("migration bookkeeping: %v", err)
	}
	if version != uniquenessVersion || !dirty {
		t.Fatalf("after the refusal the bookkeeping is version=%d dirty=%v, want version=%d dirty=true",
			version, dirty, uniquenessVersion)
	}
}

// TestUniquenessMigrationRefusalNamesEveryLevel: ONE refusal, naming every offending group at
// every level. A migration that reported the first level only would send an operator through
// three upgrade attempts to discover three problems.
func TestUniquenessMigrationRefusalNamesEveryLevel(t *testing.T) {
	pool := newPool(t)
	withoutUniquenessIndexes(t, pool)

	// products: one case-folded duplicate group, plus a wide group that exceeds the id cap.
	mustExec(t, pool, insertProductSQL, "prod-x-1", "X")
	mustExec(t, pool, insertProductSQL, "prod-x-2", "x")
	for i := 0; i < 12; i++ {
		mustExec(t, pool, insertProductSQL, fmt.Sprintf("prod-wide-%02d", i), "Wide")
	}
	// projects: duplicate under one product (a product that is itself fine).
	mustExec(t, pool, insertProductSQL, "prod-base", "Base")
	mustExec(t, pool, insertProjectSQL, "proj-svc-1", "prod-base", "Svc")
	mustExec(t, pool, insertProjectSQL, "proj-svc-2", "prod-base", "svc")
	// releases: duplicate version under one project. Exact, not case-folded.
	mustExec(t, pool, insertProjectSQL, "proj-only", "prod-base", "only")
	mustExec(t, pool, insertReleaseSQL, "rel-dup-1", "proj-only", "1.2.3")
	mustExec(t, pool, insertReleaseSQL, "rel-dup-2", "proj-only", "1.2.3")

	err := migrateToErr(t, uniquenessVersion)
	if err == nil {
		t.Fatal("migrate-up succeeded over duplicates at all three levels")
	}
	for _, want := range []string{
		`products: lower(name)='x' rows=2 ids=[prod-x-1, prod-x-2]`,
		`projects: product_id='prod-base' lower(name)='svc' rows=2 ids=[proj-svc-1, proj-svc-2]`,
		`releases: project_id='proj-only' version='1.2.3' rows=2 ids=[rel-dup-1, rel-dup-2]`,
		// The ids are capped, so one wide group cannot make the refusal unreadable — and the
		// remainder is counted, so the cap never hides how big the group is.
		`products: lower(name)='wide' rows=12 ids=[prod-wide-00, prod-wide-01, prod-wide-02, prod-wide-03, prod-wide-04, prod-wide-05, prod-wide-06, prod-wide-07, prod-wide-08, prod-wide-09, +2 more]`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not contain\n  %s\ngot:\n%v", want, err)
		}
	}
	for _, name := range []string{productsNameIndex, projectsNameIndex, releasesVersionIndex} {
		if indexExists(t, pool, name) {
			t.Fatalf("%s was created although the pre-flight refused", name)
		}
	}
}

// TestRegistryUniquenessConstraintsEnforced: a duplicate insert at each level fails with 23505
// naming the expected index — and the asymmetry B4 chose deliberately holds, so a product name
// folds case while a version does not.
func TestRegistryUniquenessConstraintsEnforced(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	// The premise, asserted rather than assumed: this test is only meaningful at version 3,
	// and an insert that succeeds because the index is absent would read as a pass.
	migrateTo(t, uniquenessVersion)
	for _, name := range []string{productsNameIndex, projectsNameIndex, releasesVersionIndex} {
		if !indexExists(t, pool, name) {
			t.Fatalf("%s is absent — there is no constraint to enforce", name)
		}
	}

	mustExec(t, pool, insertProductSQL, "prod-1", "OAMP")
	_, err := pool.Exec(ctx, insertProductSQL, "prod-2", "oamp")
	assertUniqueViolation(t, err, productsNameIndex)

	mustExec(t, pool, insertProjectSQL, "proj-1", "prod-1", "Svc")
	_, err = pool.Exec(ctx, insertProjectSQL, "proj-2", "prod-1", "svc")
	assertUniqueViolation(t, err, projectsNameIndex)
	// Scoped to its product: the same project name under another product is another row.
	mustExec(t, pool, insertProductSQL, "prod-other", "Other")
	mustExec(t, pool, insertProjectSQL, "proj-other", "prod-other", "Svc")

	mustExec(t, pool, insertReleaseSQL, "rel-1", "proj-1", "R1917.256")
	_, err = pool.Exec(ctx, insertReleaseSQL, "rel-2", "proj-1", "R1917.256")
	assertUniqueViolation(t, err, releasesVersionIndex)
	// Version uniqueness is EXACT: a build string's case is not Themis's to fold, so folding
	// it here would merge two builds.
	mustExec(t, pool, insertReleaseSQL, "rel-3", "proj-1", "r1917.256")
}

// TestRegistryUniquenessMigrationReversible: up → down → up on a seeded database. Counts and
// ids are unchanged throughout (the pair touches no data), and after `down` the duplicate
// insert SUCCEEDS — which is what proves the down actually dropped the indexes rather than the
// test merely not tripping over them.
func TestRegistryUniquenessMigrationReversible(t *testing.T) {
	pool := newPool(t)
	withoutUniquenessIndexes(t, pool)
	ctx := context.Background()

	// A seeded, duplicate-free registry — the 2026-10-12 census says this is the VM's shape.
	mustExec(t, pool, insertProductSQL, "prod-a", "Alpha")
	mustExec(t, pool, insertProductSQL, "prod-b", "Beta")
	mustExec(t, pool, insertProjectSQL, "proj-a", "prod-a", "api")
	mustExec(t, pool, insertProjectSQL, "proj-b", "prod-b", "api")
	mustExec(t, pool, insertReleaseSQL, "rel-a1", "proj-a", "1.0.0")
	mustExec(t, pool, insertReleaseSQL, "rel-a2", "proj-a", "1.0.1")
	before := idSnapshot(t, pool)

	assertSnapshot := func(stage string) {
		t.Helper()
		if got := idSnapshot(t, pool); got != before {
			t.Fatalf("%s changed the data:\nbefore:\n%s\nafter:\n%s", stage, before, got)
		}
	}
	allIndexes := []string{productsNameIndex, projectsNameIndex, releasesVersionIndex}

	migrateTo(t, uniquenessVersion) // up
	assertSnapshot("up")
	for _, name := range allIndexes {
		if !indexExists(t, pool, name) {
			t.Fatalf("up did not create %s", name)
		}
	}
	_, err := pool.Exec(ctx, insertReleaseSQL, "rel-dup", "proj-a", "1.0.0")
	assertUniqueViolation(t, err, releasesVersionIndex)

	migrateTo(t, preUniquenessVersion) // down
	assertSnapshot("down")
	for _, name := range allIndexes {
		if indexExists(t, pool, name) {
			t.Fatalf("down left %s behind", name)
		}
	}
	mustExec(t, pool, insertReleaseSQL, "rel-dup", "proj-a", "1.0.0")
	// It has to go again before the second up: the pre-flight refuses duplicates, which is
	// the point of it.
	mustExec(t, pool, `DELETE FROM releases WHERE id = $1`, "rel-dup")

	migrateTo(t, uniquenessVersion) // up again
	assertSnapshot("re-up")
	_, err = pool.Exec(ctx, insertReleaseSQL, "rel-dup", "proj-a", "1.0.0")
	assertUniqueViolation(t, err, releasesVersionIndex)
}
