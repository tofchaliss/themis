package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestHealthz(t *testing.T) {
	s := testServer(t, ReadinessChecker{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadyzReady(t *testing.T) {
	s := testServer(t, ReadinessChecker{
		DBPing: func(context.Context) error { return nil },
		CVEFeedLastSuccess: func() time.Time {
			return time.Now()
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadyzDatabaseFailure(t *testing.T) {
	s := testServer(t, ReadinessChecker{
		DBPing: func(context.Context) error { return errors.New("db down") },
		CVEFeedLastSuccess: func() time.Time {
			return time.Now()
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestReadyzMissingCVEFeed(t *testing.T) {
	s := testServer(t, ReadinessChecker{
		DBPing:             func(context.Context) error { return nil },
		CVEFeedLastSuccess: func() time.Time { return time.Time{} },
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestServerStartAndShutdown(t *testing.T) {
	s := New("127.0.0.1:0", zap.NewNop(), ReadinessChecker{}, time.Second, time.Second)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.httpServer.Addr != ":0" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("Start() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server shutdown")
	}
}

func TestNoopWorkerPool(t *testing.T) {
	var pool NoopWorkerPool
	if err := pool.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := pool.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func testServer(t *testing.T, readiness ReadinessChecker) *Server {
	t.Helper()
	logger := zap.NewNop()
	return New(":0", logger, readiness, time.Second, time.Second)
}
