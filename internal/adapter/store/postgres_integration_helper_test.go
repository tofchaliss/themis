//go:build integration

package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/store"
)

var (
	sharedPostgresDSN    string
	sharedPostgresStop   func() error
	sharedPostgresFailed bool
)

func isTestListMode() bool {
	for _, arg := range os.Args {
		if arg == "-test.list" || strings.HasPrefix(arg, "-test.list=") {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		sharedPostgresDSN = dsn
		os.Exit(m.Run())
	}
	if isTestListMode() {
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "themis-store-integration-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(15432).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{
			"shared_buffers":  "128kB",
			"max_connections": "10",
		})

	dbInstance := embeddedpostgres.NewDatabase(cfg)
	startErr := make(chan error, 1)
	go func() { startErr <- dbInstance.Start() }()
	select {
	case err := <-startErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "shared postgres unavailable, skipping integration DB tests: %v\n", err)
			sharedPostgresFailed = true
			os.Exit(m.Run())
		}
	case <-time.After(30 * time.Second):
		fmt.Fprintf(os.Stderr, "shared postgres start timed out, skipping integration DB tests\n")
		sharedPostgresFailed = true
		os.Exit(m.Run())
	}
	sharedPostgresDSN = "postgres://themis:themis@localhost:15432/themis?sslmode=disable"
	sharedPostgresStop = dbInstance.Stop
	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := runIntegrationMigrationsUp(sharedPostgresDSN, migrationsPath); err != nil {
		panic(fmt.Errorf("apply shared integration migrations: %w", err))
	}

	code := m.Run()
	_ = dbInstance.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func integrationDatabaseDSN(t *testing.T, port uint32) string {
	t.Helper()
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		return dsn
	}
	if sharedPostgresFailed {
		t.Skip("embedded postgres unavailable (set THEMIS_TEST_DATABASE_DSN for external Postgres)")
	}
	if sharedPostgresDSN != "" {
		return sharedPostgresDSN
	}
	return startEmbeddedPostgres(t, port)
}

func resetIntegrationDatabase(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DO $$
		DECLARE r RECORD;
		BEGIN
			FOR r IN (
				SELECT tablename FROM pg_tables
				WHERE schemaname = 'public' AND tablename <> 'schema_migrations'
			) LOOP
				EXECUTE 'TRUNCATE TABLE ' || quote_ident(r.tablename) || ' RESTART IDENTITY CASCADE';
			END LOOP;
		END $$;
	`)
	if err != nil {
		t.Fatalf("truncate integration database: %v", err)
	}
}

func startEmbeddedPostgres(t *testing.T, port uint32) string {
	t.Helper()

	dir := t.TempDir()
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(port).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{
			"shared_buffers":  "128kB",
			"max_connections": "10",
		})

	var lastErr error
	for attempt := range 5 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		dbInstance := embeddedpostgres.NewDatabase(cfg)
		if err := dbInstance.Start(); err != nil {
			lastErr = err
			continue
		}
		t.Cleanup(func() {
			_ = dbInstance.Stop()
		})
		return "postgres://themis:themis@localhost:" + strconv.FormatUint(uint64(port), 10) + "/themis?sslmode=disable"
	}
	t.Skipf("embedded postgres unavailable (set THEMIS_TEST_DATABASE_DSN for external Postgres): %v", lastErr)
	return ""
}

// seedScan creates one sboms row + one scan_reports row for an artifact and returns both ids.
func seedScan(t *testing.T, ctx context.Context, pool *pgxpool.Pool, artifactID string) (sbomID, scanReportID string) {
	t.Helper()
	sbomID = uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO sboms (id, artifact_id, sbom_checksum, format, raw_document)
		VALUES ($1, $2, $3, 'cyclonedx', '{}')
	`, sbomID, artifactID, "sum-"+sbomID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	scanReportID = uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO scan_reports (id, sbom_id, artifact_id, image_digest, scan_checksum)
		SELECT $1, $2, $3, a.image_digest, $4 FROM artifacts a WHERE a.id = $3
	`, scanReportID, sbomID, artifactID, "scan-"+scanReportID); err != nil {
		t.Fatalf("seed scan report: %v", err)
	}
	return sbomID, scanReportID
}

// addFinding seeds a component + version + vulnerability + component_vulnerabilities row
// (with denormalized version-qualified component_purl + cve_id) on an existing scan, plus an
// identity-keyed risk_context row. Returns the version-qualified PURL so callers can assert by
// the stable identity (artifactID, versionedPURL, cveID). effectiveState defaults to "detected".
func addFinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool, artifactID, sbomID, scanReportID, basePURL, version, cveID, severity, effectiveState string) (versionedPURL string) {
	t.Helper()
	if effectiveState == "" {
		effectiveState = "detected"
	}
	versionedPURL = basePURL
	if version != "" {
		versionedPURL = basePURL + "@" + version
	}

	var componentID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO components (id, purl, name, ecosystem)
		VALUES ($1, $2, $3, 'apk')
		ON CONFLICT (purl) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`, uuid.NewString(), basePURL, basePURL).Scan(&componentID); err != nil {
		t.Fatalf("seed component: %v", err)
	}
	componentVersionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_versions (id, component_id, version, sbom_id)
		VALUES ($1, $2, $3, $4)
	`, componentVersionID, componentID, version, sbomID); err != nil {
		t.Fatalf("seed component version: %v", err)
	}

	var vulnID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO vulnerabilities (id, cve_id, severity)
		VALUES ($1, $2, $3)
		ON CONFLICT (cve_id) DO UPDATE SET severity = EXCLUDED.severity
		RETURNING id
	`, uuid.NewString(), cveID, severity).Scan(&vulnID); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_vulnerabilities (id, component_version_id, vulnerability_id, scan_report_id, component_purl, cve_id)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, uuid.NewString(), componentVersionID, vulnID, scanReportID, versionedPURL, cveID); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO risk_context (artifact_id, component_purl, cve_id, effective_state, priority, risk_score, raw_severity)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (artifact_id, component_purl, cve_id) DO UPDATE SET effective_state = EXCLUDED.effective_state
	`, artifactID, versionedPURL, cveID, effectiveState, severity, 40, severity); err != nil {
		t.Fatalf("seed risk context: %v", err)
	}
	return versionedPURL
}

// seedFinding is a convenience wrapper: one scan with a single finding. Returns the scan
// report id and the version-qualified PURL.
func seedFinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool, artifactID, basePURL, version, cveID, severity, effectiveState string) (scanReportID, versionedPURL string) {
	t.Helper()
	sbomID, scanReportID := seedScan(t, ctx, pool, artifactID)
	versionedPURL = addFinding(t, ctx, pool, artifactID, sbomID, scanReportID, basePURL, version, cveID, severity, effectiveState)
	return scanReportID, versionedPURL
}

func runIntegrationMigrationsUp(dsn, migrationsPath string) error {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = m.Close()
	}()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	version, dirty, err := m.Version()
	if err != nil {
		return err
	}
	return store.CompareSchemaVersion(version, dirty, store.BinarySchemaVersion)
}

func applyIntegrationMigrations(dsn, migrationsPath string) error {
	if dsn == sharedPostgresDSN && sharedPostgresDSN != "" {
		return nil
	}
	return runIntegrationMigrationsUp(dsn, migrationsPath)
}
