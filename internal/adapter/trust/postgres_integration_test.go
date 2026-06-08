//go:build integration

package trust

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/themis-project/themis/internal/domain"
)

func startEmbeddedPostgresAtPort(t *testing.T, port uint32) string {
	t.Helper()

	dir := t.TempDir()
	dbInstance := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(port).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		CachePath(filepath.Join(dir, "cache")).
		StartParameters(map[string]string{
			"shared_buffers":  "128kB",
			"max_connections": "10",
		}))
	if err := dbInstance.Start(); err != nil {
		t.Skipf("embedded postgres unavailable (set THEMIS_TEST_DATABASE_DSN for external Postgres): %v", err)
	}
	t.Cleanup(func() { _ = dbInstance.Stop() })

	return "postgres://themis:themis@localhost:" + strconv.FormatUint(uint64(port), 10) + "/themis?sslmode=disable"
}

func setupTrustPostgres(t *testing.T, port uint32) (*pgxpool.Pool, *PostgresRepository, *PostgresAuditRecorder) {
	t.Helper()

	dsn := startEmbeddedPostgresAtPort(t, port)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := runMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return pool, NewPostgresRepository(pool), NewPostgresAuditRecorder(pool)
}

func TestPostgresRepositoryQueries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	ctx := context.Background()
	pool, repo, audit := setupTrustPostgres(t, 15441)
	t.Cleanup(pool.Close)

	if _, found, err := repo.FindVEXByDedupKey(ctx, "missing", "missing"); err != nil || found {
		t.Fatalf("FindVEXByDedupKey() = found=%v err=%v", found, err)
	}
	if exists, err := repo.ImageDigestExists(ctx, "sha256:none"); err != nil || exists {
		t.Fatalf("ImageDigestExists() = %v, %v", exists, err)
	}
	if exists, err := repo.SBOMChecksumExists(ctx, "none"); err != nil || exists {
		t.Fatalf("SBOMChecksumExists() = %v, %v", exists, err)
	}
	if _, found, err := repo.FindSBOMByDedupKey(ctx, "sha256:none", "none"); err != nil || found {
		t.Fatalf("FindSBOMByDedupKey() = found=%v err=%v", found, err)
	}

	entry := domain.AuditEntry{
		Actor:        "tester",
		Action:       domain.AuditActionArtifactAccepted,
		ResourceType: "sbom",
		ResourceID:   "not-a-uuid",
		Details:      map[string]string{"message": "ok"},
		SourceIP:     "127.0.0.1",
	}
	if err := audit.Record(ctx, entry); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if _, err := audit.CountByAction(ctx, domain.AuditActionArtifactAccepted); err != nil {
		t.Fatalf("CountByAction() error = %v", err)
	}
}
