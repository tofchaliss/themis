package httpserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/themis-project/themis/internal/infrastructure/queue"
)

func TestRunReturnsBootError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("THEMIS_CONFIG_PATH", path)
	if err := Run(context.Background()); err == nil {
		t.Fatal("expected Run() to fail when database DSN is missing")
	}
}

func TestWaitForShutdownOnSignal(t *testing.T) {
	logger := zap.NewNop()
	s := New(":0", logger, ReadinessChecker{}, time.Second, time.Second)
	app := &Application{
		Config:     configDefault(t),
		Logger:     logger,
		Workers:    queue.NoopWorkerPool{},
		HTTPServer: s,
		DB:         stubPool{},
	}

	errCh := make(chan error, 1)
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGINT

	if err := waitForShutdown(context.Background(), logger, app, errCh, sigCh); err != nil {
		t.Fatalf("waitForShutdown() error = %v", err)
	}
}

func TestWaitForShutdownOnServerError(t *testing.T) {
	logger := zap.NewNop()
	errCh := make(chan error, 1)
	errCh <- errors.New("listen failed")
	sigCh := make(chan os.Signal, 1)

	err := waitForShutdown(context.Background(), logger, &Application{}, errCh, sigCh)
	if err == nil {
		t.Fatal("expected server error")
	}
}

func TestWaitForShutdownCleanServerExit(t *testing.T) {
	errCh := make(chan error, 1)
	errCh <- nil
	sigCh := make(chan os.Signal, 1)

	if err := waitForShutdown(context.Background(), zap.NewNop(), &Application{}, errCh, sigCh); err != nil {
		t.Fatalf("waitForShutdown() error = %v", err)
	}
}

func TestRunSuccess(t *testing.T) {
	origBoot := bootFn
	origWait := waitForShutdown
	t.Cleanup(func() {
		bootFn = origBoot
		waitForShutdown = origWait
	})

	logger := zap.NewNop()
	s := New(":0", logger, ReadinessChecker{}, time.Second, time.Second)
	app := &Application{
		Config:     configDefault(t),
		Logger:     logger,
		Workers:    queue.NoopWorkerPool{},
		HTTPServer: s,
		DB:         stubPool{},
	}
	bootFn = func(context.Context, *zap.Logger, ...BootOption) (*Application, error) {
		return app, nil
	}
	waitForShutdown = func(context.Context, *zap.Logger, *Application, <-chan error, <-chan os.Signal) error {
		return nil
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	if err := os.WriteFile(path, []byte("database:\n  dsn: postgres://localhost/themis\nlog:\n  level: warn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THEMIS_CONFIG_PATH", path)
	t.Setenv("THEMIS_LOG_LEVEL", "")

	if err := Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunLoggerBuildError(t *testing.T) {
	orig := buildZapLogger
	t.Cleanup(func() { buildZapLogger = orig })
	buildZapLogger = func(zap.Config) (*zap.Logger, error) {
		return nil, errors.New("logger build failed")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "themis.yaml")
	if err := os.WriteFile(path, []byte("database:\n  dsn: postgres://localhost/themis\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THEMIS_CONFIG_PATH", path)
	t.Setenv("THEMIS_LOG_LEVEL", "debug")

	if err := Run(context.Background()); err == nil {
		t.Fatal("expected logger build error")
	}
}
