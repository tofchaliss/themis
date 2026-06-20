package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/config"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

type stubPool struct{}

func (stubPool) Ping(context.Context) error { return nil }
func (stubPool) Close()                     {}

type failingWorkerStartPool struct{}

func (failingWorkerStartPool) Start(context.Context) error { return errors.New("worker start failed") }
func (failingWorkerStartPool) Stop(context.Context) error  { return nil }

type failingWorkerStopPool struct{}

func (failingWorkerStopPool) Start(context.Context) error { return nil }
func (failingWorkerStopPool) Stop(context.Context) error  { return errors.New("worker stop failed") }

func TestBootRequiresDatabaseDSN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 8081\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Boot(context.Background(), zap.NewNop(), WithConfigPath(path))
	if err == nil {
		t.Fatal("expected boot error without database dsn")
	}
}

func TestBootSuccess(t *testing.T) {
	path := writeConfig(t, "server:\n  port: 8081\n")
	cfg := bootConfig{
		configPath:     path,
		migrationsPath: "migrations",
		workerPool:     queue.NoopWorkerPool{},
		hooks: bootHooks{
			connect: func(context.Context, string, int32) (domain.DatabasePool, error) {
				return stubPool{}, nil
			},
			runMigrations:       func(string, string) error { return nil },
			verifySchemaVersion: func(string, string) error { return nil },
		},
	}

	app, err := bootWithConfig(context.Background(), zap.NewNop(), cfg)
	if err != nil {
		t.Fatalf("bootWithConfig() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = app.Close(ctx)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	app.HTTPServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rec.Code)
	}
}

func TestBootConnectFailure(t *testing.T) {
	path := writeConfig(t, "")
	cfg := bootConfig{
		configPath: path,
		hooks: bootHooks{
			connect: func(context.Context, string, int32) (domain.DatabasePool, error) {
				return nil, errors.New("connect failed")
			},
		},
	}
	_, err := bootWithConfig(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected connect failure")
	}
}

func TestBootMigrationFailure(t *testing.T) {
	path := writeConfig(t, "")
	cfg := bootConfig{
		configPath: path,
		hooks: bootHooks{
			connect: func(context.Context, string, int32) (domain.DatabasePool, error) {
				return stubPool{}, nil
			},
			runMigrations: func(string, string) error { return errors.New("migrate failed") },
		},
	}
	_, err := bootWithConfig(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected migration failure")
	}
}

func TestBootVerifySchemaFailure(t *testing.T) {
	path := writeConfig(t, "")
	cfg := bootConfig{
		configPath: path,
		hooks: bootHooks{
			connect: func(context.Context, string, int32) (domain.DatabasePool, error) {
				return stubPool{}, nil
			},
			runMigrations:       func(string, string) error { return nil },
			verifySchemaVersion: func(string, string) error { return errors.New("schema verify failed") },
		},
	}
	_, err := bootWithConfig(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected schema verify failure")
	}
}

func TestBootRequiresPgxPoolForDefaultWorkers(t *testing.T) {
	path := writeConfig(t, "")
	cfg := bootConfig{
		configPath: path,
		hooks: bootHooks{
			connect: func(context.Context, string, int32) (domain.DatabasePool, error) {
				return stubPool{}, nil
			},
			runMigrations:       func(string, string) error { return nil },
			verifySchemaVersion: func(string, string) error { return nil },
		},
	}
	_, err := bootWithConfig(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected pgx pool type error")
	}
}

func TestBootWorkerStartFailure(t *testing.T) {
	path := writeConfig(t, "")
	cfg := bootConfig{
		configPath: path,
		workerPool: failingWorkerStartPool{},
		hooks: bootHooks{
			connect: func(context.Context, string, int32) (domain.DatabasePool, error) {
				return stubPool{}, nil
			},
			runMigrations:       func(string, string) error { return nil },
			verifySchemaVersion: func(string, string) error { return nil },
		},
	}
	_, err := bootWithConfig(context.Background(), zap.NewNop(), cfg)
	if err == nil {
		t.Fatal("expected worker start failure")
	}
}

func TestBootOptions(t *testing.T) {
	var cfg bootConfig
	WithConfigPath("a.yaml")(&cfg)
	WithMigrationsPath("migrations")(&cfg)
	WithWorkerPool(queue.NoopWorkerPool{})(&cfg)
	if cfg.configPath != "a.yaml" || cfg.migrationsPath != "migrations" {
		t.Fatal("boot options not applied")
	}
}

func TestBootWithConfigMountsAPI(t *testing.T) {
	path := writeConfig(t, "")
	workers, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
		Store:     queue.NewMemoryJobStore(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := bootConfig{
		configPath: path,
		workerPool: workers,
		hooks: bootHooks{
			connect: func(context.Context, string, int32) (domain.DatabasePool, error) {
				return bootMountPool{}, nil
			},
			runMigrations:       func(string, string) error { return nil },
			verifySchemaVersion: func(string, string) error { return nil },
		},
	}
	app, err := bootWithConfig(context.Background(), zap.NewNop(), cfg)
	if err != nil {
		t.Fatalf("bootWithConfig() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = app.Close(ctx)
	})
	if app.HTTPServer == nil || app.HTTPServer.Router() == nil {
		t.Fatal("expected mounted API router")
	}
}

type bootMountPool struct{ mountFakePool }

func (bootMountPool) Ping(context.Context) error { return nil }
func (bootMountPool) Close()                     {}

func TestApplicationCloseWorkerFailure(t *testing.T) {
	logger := zap.NewNop()
	s := New(":0", logger, ReadinessChecker{
		DBPing:             func(context.Context) error { return nil },
		CVEFeedLastSuccess: func() time.Time { return time.Now() },
	}, time.Second, time.Second)

	app := &Application{
		Config:     configDefault(t),
		Logger:     logger,
		DB:         stubPool{},
		Workers:    failingWorkerStopPool{},
		HTTPServer: s,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := app.Close(ctx); err == nil {
		t.Fatal("expected worker stop error")
	}
}

func TestApplicationCloseInProcessWorkers(t *testing.T) {
	store := queue.NewMemoryJobStore()
	workers, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize: 1,
		MaxRetry: 1,
		Store:    store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := workers.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	logger := zap.NewNop()
	s := New(":0", logger, ReadinessChecker{
		DBPing:             func(context.Context) error { return nil },
		CVEFeedLastSuccess: func() time.Time { return time.Now() },
	}, time.Second, time.Second)

	app := &Application{
		Config:     configDefault(t),
		Logger:     logger,
		DB:         stubPool{},
		Workers:    workers,
		HTTPServer: s,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := app.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestApplicationClose(t *testing.T) {
	logger := zap.NewNop()
	s := New(":0", logger, ReadinessChecker{
		DBPing:             func(context.Context) error { return nil },
		CVEFeedLastSuccess: func() time.Time { return time.Now() },
	}, time.Second, time.Second)

	app := &Application{
		Config:     configDefault(t),
		Logger:     logger,
		DB:         stubPool{},
		Workers:    queue.NoopWorkerPool{},
		HTTPServer: s,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := app.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewReadinessFromPool(t *testing.T) {
	var ts atomic.Value
	ts.Store(time.Now())
	checker := NewReadinessFromPool(stubPool{}, &ts)
	if err := checker.DBPing(context.Background()); err != nil {
		t.Fatal(err)
	}
	if checker.CVEFeedLastSuccess().IsZero() {
		t.Fatal("expected CVE timestamp")
	}

	checker = NewReadinessFromPool(stubPool{}, nil)
	if !checker.CVEFeedLastSuccess().IsZero() {
		t.Fatal("expected zero CVE timestamp")
	}

	var badTS atomic.Value
	badTS.Store("not-a-time")
	checker = NewReadinessFromPool(stubPool{}, &badTS)
	if !checker.CVEFeedLastSuccess().IsZero() {
		t.Fatal("expected zero CVE timestamp for invalid atomic value")
	}
}

func TestDefaultBootHooks(t *testing.T) {
	hooks := defaultBootHooks()
	if _, err := hooks.connect(context.Background(), "not-a-dsn", 1); err == nil {
		t.Fatal("expected default connect hook error")
	}
}

func TestApplicationCloseShutdownFailure(t *testing.T) {
	orig := shutdownHTTPServer
	t.Cleanup(func() { shutdownHTTPServer = orig })
	shutdownHTTPServer = func(*Server, context.Context) error {
		return errors.New("shutdown failed")
	}

	logger := zap.NewNop()
	s := New(":0", logger, ReadinessChecker{}, time.Second, time.Second)
	app := &Application{
		Logger:     logger,
		DB:         stubPool{},
		Workers:    queue.NoopWorkerPool{},
		HTTPServer: s,
	}
	if err := app.Close(context.Background()); err == nil {
		t.Fatal("expected shutdown error")
	}
}

func writeConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	content := "database:\n  dsn: postgres://localhost/themis\n" + extra
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func configDefault(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(writeConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
