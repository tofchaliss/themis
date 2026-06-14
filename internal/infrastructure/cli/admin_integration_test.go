//go:build integration

package cli_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/adapter/api"
	apimiddleware "github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/cli"
)

func TestRunAdminCLIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15462)
	t.Setenv("THEMIS_DATABASE_DSN", dsn)
	t.Setenv("THEMIS_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.yaml"))

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := applyIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	ctx := context.Background()
	if err := cli.RunAdmin(ctx, []string{"create-key", "--admin", "--name", "cli-admin"}); err != nil {
		t.Fatalf("create-key cli: %v", err)
	}
}

func TestAPIKeyLifecycleIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15460)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := applyIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	repo := store.NewPostgresAPIKeyRepository(pool)
	productID := "11111111-1111-4111-8111-111111111111"
	result, err := cli.CreateKey(ctx, repo, cli.CreateKeyOptions{
		Name:      "integration",
		ProductID: productID,
	}, nil, func(raw string) (string, error) {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
		if hashErr != nil {
			return "", hashErr
		}
		return string(hash), nil
	})
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	var storedHash string
	if err := pool.QueryRow(ctx, `SELECT key_hash FROM api_keys WHERE id = $1`, result.ID).Scan(&storedHash); err != nil {
		t.Fatalf("load key hash: %v", err)
	}
	if storedHash == result.RawKey {
		t.Fatal("expected bcrypt hash, not plaintext")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(result.RawKey)); err != nil {
		t.Fatalf("bcrypt compare: %v", err)
	}

	handler := api.NewHandler(api.Dependencies{
		Catalog: &integrationCatalog{productID: productID},
	})
	router := mountIntegrationAPI(handler, repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+productID+"/projects", nil)
	req.Header.Set("X-API-Key", result.RawKey)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized status=%d body=%s", rec.Code, rec.Body.String())
	}

	if err := cli.RevokeKey(ctx, repo, result.ID); err != nil {
		t.Fatalf("revoke key: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/"+productID+"/projects", nil)
	req.Header.Set("X-API-Key", result.RawKey)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func mountIntegrationAPI(handler *api.Handler, keys domain.APIKeyRepository) http.Handler {
	r := chi.NewRouter()
	api.Mount(r, api.MountConfig{
		Handler:       handler,
		APIKeyAuth:    apimiddleware.APIKeyAuth{Keys: keys},
		MaxUploadSize: 1024 * 1024,
	})
	return r
}

type integrationCatalog struct {
	productID string
}

func (c *integrationCatalog) CreateProduct(context.Context, string, string) (domain.Product, error) {
	return domain.Product{}, nil
}
func (c *integrationCatalog) ListProducts(context.Context, domain.PageRequest, string) ([]domain.Product, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}
func (c *integrationCatalog) GetProduct(context.Context, string) (domain.Product, error) {
	return domain.Product{}, nil
}
func (c *integrationCatalog) CreateProject(context.Context, string, string, string) (domain.Project, error) {
	return domain.Project{}, nil
}
func (c *integrationCatalog) ListProjects(_ context.Context, productID string, _ domain.PageRequest) ([]domain.Project, domain.PageResult, error) {
	if productID != c.productID {
		return nil, domain.PageResult{}, nil
	}
	return []domain.Project{{ID: "p1", ProductID: productID, Name: "app"}}, domain.PageResult{}, nil
}
func (c *integrationCatalog) ListProductVersions(context.Context, string, domain.PageRequest) ([]domain.ProductVersion, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}

func integrationDatabaseDSN(t *testing.T, port uint32) string {
	t.Helper()
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		return dsn
	}
	return startEmbeddedPostgres(t, port)
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

func applyIntegrationMigrations(dsn, migrationsPath string) error {
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
	return nil
}
