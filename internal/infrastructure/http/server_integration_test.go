//go:build integration

package httpserver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
)

var errUnavailable = errors.New("database unavailable")

func TestServerHealthIntegration(t *testing.T) {
	dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("THEMIS_TEST_DATABASE_DSN not set")
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "themis.yaml")
	cfg := `
server:
  port: 18080
database:
  dsn: ` + dsn + `
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	app, err := httpserver.Boot(
		context.Background(),
		zap.NewNop(),
		httpserver.WithConfigPath(cfgPath),
		httpserver.WithMigrationsPath(migrationsPath),
	)
	if err != nil {
		t.Fatalf("Boot() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = app.Close(ctx)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	app.HTTPServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	app.HTTPServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200", rec.Code)
	}
}

func TestServerReadyzWithoutDatabaseIntegration(t *testing.T) {
	logger := zap.NewNop()
	s := httpserver.New(":0", logger, httpserver.ReadinessChecker{
		DBPing:             func(context.Context) error { return errUnavailable },
		CVEFeedLastSuccess: func() time.Time { return time.Now() },
	}, time.Second, time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503", rec.Code)
	}
}
