//go:build integration

package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

	"github.com/themis-project/themis/internal/registry/adapters/wiring"
)

// The status code and the body's `created` flag are two statements about one event, and only a
// real database can put them under contention: a fake repository hands out the "I created it"
// answer inside a map the handler never races for. This file drives the PRODUCTION wiring
// (wiring.RegistryAPI → the pgx Store's `INSERT … ON CONFLICT`) over embedded PostgreSQL, so
// the thing under test is the one an operator runs.

var registryDSN string

// registryMigrationsTable mirrors cmd/registry: Registry co-locates its identity tables in the
// `evidence` database, so it keeps its OWN golang-migrate bookkeeping table. The tests migrate
// through the same configuration the node uses.
const registryMigrationsTable = "registry_schema_migrations"

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		registryDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "registry-http-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15534).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"shared_buffers": "128kB", "max_connections": "10"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		// Run the package's tests anyway: the database-backed ones skip on an empty DSN, and
		// swallowing the rest here would report the whole package as having no coverage.
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping registry http integration tests: %v\n", err)
		os.Exit(m.Run())
	}
	registryDSN = "postgres://themis:themis@localhost:15534/themis?sslmode=disable"
	if err := migrateUp(registryDSN); err != nil {
		_ = db.Stop()
		panic(err)
	}
	code := m.Run()
	_ = db.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func migrateUp(dsn string) error {
	path, err := filepath.Abs("../store/migrations")
	if err != nil {
		return err
	}
	// The migrations-table parameter MUST ride a separate DSN string from the pool's: pgx
	// forwards an unknown parameter to Postgres as a startup option and every runtime
	// connection would fail with `unrecognized configuration parameter`.
	u, err := url.Parse(dsn)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("x-migrations-table", registryMigrationsTable)
	u.RawQuery = q.Encode()

	mig, err := migrate.New("file://"+path, u.String())
	if err != nil {
		return err
	}
	defer func() { _, _ = mig.Close() }()
	if err := mig.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// liveRegistry serves the production wiring over the test database and returns the server plus
// the pool, so a test can both drive the API and count rows behind it.
//
// The pool is capped: the embedded server runs with a small max_connections, and a test that
// fires more callers than that would fail on connection exhaustion — which reads exactly like
// the upsert erroring. Callers above the cap queue on the pool (bounded by their context) and
// still contend for real.
func liveRegistry(t *testing.T) (*httptest.Server, *pgxpool.Pool) {
	t.Helper()
	if registryDSN == "" {
		t.Skip("no database")
	}
	cfg, err := pgxpool.ParseConfig(registryDSN)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.MaxConns = 6
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	truncateRegistry(t, pool)
	handler, _ := wiring.RegistryAPI(pool)
	srv := httptest.NewServer(handler)
	t.Cleanup(func() {
		srv.Close()
		truncateRegistry(t, pool)
		pool.Close()
	})
	return srv, pool
}

func truncateRegistry(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		"TRUNCATE deployments, microservices, customers, releases, projects, products RESTART IDENTITY CASCADE")
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// createResult is one caller's answer: the status it was given, the id and `created` flag in
// the body, and whether the call failed before producing either.
type createResult struct {
	status  int
	id      string
	created bool
	err     error
}

func postCreate(ctx context.Context, url string, body map[string]string) createResult {
	raw, err := json.Marshal(body)
	if err != nil {
		return createResult{err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return createResult{err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return createResult{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return createResult{status: resp.StatusCode, err: err}
	}
	var out struct {
		Id      string `json:"id"`
		Created bool   `json:"created"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return createResult{status: resp.StatusCode, err: fmt.Errorf("decode %q: %w", payload, err)}
	}
	return createResult{status: resp.StatusCode, id: out.Id, created: out.Created}
}

// mustCreate drives one create route and insists it created the row — the sequential parent
// chain the raced Release hangs off.
func mustCreate(ctx context.Context, t *testing.T, url string, body map[string]string) string {
	t.Helper()
	got := postCreate(ctx, url, body)
	if got.err != nil {
		t.Fatalf("POST %s: %v", url, got.err)
	}
	if got.status != http.StatusCreated || !got.created || got.id == "" {
		t.Fatalf("POST %s = %d created=%v id=%q, want 201 created=true", url, got.status, got.created, got.id)
	}
	return got.id
}

// TestConcurrentCreateStatusAgreesWithCreatedFlag is the property the unique indexes exist for,
// seen from the edge a bot actually calls: N clients register the same version at the same
// instant, and exactly ONE of them is told it created the Release. Every other caller gets
// `200` with `created=false` and the SAME id — no error, no second row, no forked Release
// (EDR-INTAKE-01 B4).
//
// The status and the flag are asserted together on purpose. Either one alone would pass if the
// handler mapped a stale `created` to a fresh `201`, and a client that trusted the other half
// would then record a creation that never happened.
func TestConcurrentCreateStatusAgreesWithCreatedFlag(t *testing.T) {
	// Every wait is bounded by this context, so a regression fails instead of hanging the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srv, pool := liveRegistry(t)

	productID := mustCreate(ctx, t, srv.URL+"/products", map[string]string{"name": "OAMP"})
	projectID := mustCreate(ctx, t, srv.URL+"/projects",
		map[string]string{"product_id": productID, "name": "core"})

	const callers = 20
	const version = "R1917.256"
	body := map[string]string{"project_id": projectID, "version": version}

	// The shared start channel matters: goroutines started in a loop would otherwise serialize
	// and the race this test exists to cover would never be attempted.
	results := make([]createResult, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = postCreate(ctx, srv.URL+"/releases", body)
		}(i)
	}
	close(start)
	wg.Wait()

	creators, id := 0, ""
	for i, got := range results {
		if got.err != nil {
			t.Fatalf("caller %d failed: %v", i, got.err)
		}
		if got.id == "" {
			t.Fatalf("caller %d returned an empty id (status %d)", i, got.status)
		}
		if id == "" {
			id = got.id
		} else if got.id != id {
			t.Errorf("caller %d id = %q, want the single surviving %q", i, got.id, id)
		}
		switch {
		case got.created && got.status != http.StatusCreated:
			t.Errorf("caller %d: created=true answered %d, want 201", i, got.status)
		case !got.created && got.status != http.StatusOK:
			t.Errorf("caller %d: created=false answered %d, want 200", i, got.status)
		}
		if got.created {
			creators++
		}
	}
	if creators != 1 {
		t.Errorf("callers reporting created=true = %d, want exactly 1", creators)
	}

	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM releases WHERE project_id = $1 AND version = $2`,
		projectID, version).Scan(&rows); err != nil {
		t.Fatalf("count releases: %v", err)
	}
	if rows != 1 {
		t.Errorf("releases at %s = %d, want exactly 1", version, rows)
	}
}
