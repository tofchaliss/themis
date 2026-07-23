package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// captured builds a Logger over an in-memory observer core at the given level.
func captured(level zapcore.Level) (*Logger, *observer.ObservedLogs) {
	core, logs := observer.New(level)
	return &Logger{z: zap.New(core)}, logs
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("THEMIS_LOG_LEVEL", "warn")
	t.Setenv("THEMIS_LOG_FORMAT", "console")
	t.Setenv("THEMIS_OTLP_LOGS_ENDPOINT", "collector:4318")
	t.Setenv("THEMIS_OTLP_INSECURE", "1")

	cfg := ConfigFromEnv("evidence")
	if cfg.Service != "evidence" || cfg.Level != "warn" || cfg.Format != "console" ||
		cfg.OTLPEndpoint != "collector:4318" || !cfg.OTLPInsecure {
		t.Errorf("config = %+v", cfg)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]zapcore.Level{
		"debug": zapcore.DebugLevel, "info": zapcore.InfoLevel,
		"warn": zapcore.WarnLevel, "warning": zapcore.WarnLevel,
		"error": zapcore.ErrorLevel, "": zapcore.InfoLevel, "bogus": zapcore.InfoLevel,
		"  DEBUG  ": zapcore.DebugLevel,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLoggerLevelsAndFields(t *testing.T) {
	log, logs := captured(zapcore.InfoLevel)

	log.Debug("dropped") // below the min level
	log.Info("hello", String("k", "v"), Int("n", 1))
	log.Warn("careful")
	log.Error("boom", Err(context.Canceled))

	if logs.Len() != 3 {
		t.Fatalf("recorded %d, want 3 (debug filtered)", logs.Len())
	}
	first := logs.All()[0]
	if first.Message != "hello" || first.ContextMap()["k"] != "v" || first.ContextMap()["n"] != int64(1) {
		t.Errorf("entry = %+v", first)
	}

	// With / Component attach fields to every subsequent record.
	child := log.With(String("correlation_id", "cid-1")).Component("relay")
	child.Info("worked")
	last := logs.All()[logs.Len()-1]
	if last.ContextMap()["correlation_id"] != "cid-1" || last.ContextMap()["component"] != "relay" {
		t.Errorf("child fields = %+v", last.ContextMap())
	}
}

func TestFieldConstructorsAndSync(t *testing.T) {
	log, logs := captured(zapcore.DebugLevel)
	log.Debug("f", Int64("i", 2), Bool("b", true), Duration("d", time.Second), Any("a", []int{1}))
	if logs.Len() != 1 {
		t.Fatalf("recorded %d, want 1", logs.Len())
	}
	m := logs.All()[0].ContextMap()
	if m["i"] != int64(2) || m["b"] != true {
		t.Errorf("fields = %+v", m)
	}
	_ = log.Sync() // no-op on the observer; must not panic
}

func TestLeveledCoreFiltersOTelChannel(t *testing.T) {
	inner, logs := observer.New(zapcore.DebugLevel) // the inner core would accept everything
	lc := leveledCore{Core: inner, level: zapcore.WarnLevel}
	z := zap.New(lc)

	z.Info("dropped by the level wrapper")
	z.Warn("kept")
	z.Error("kept")

	if logs.Len() != 2 {
		t.Fatalf("leveledCore recorded %d, want 2 (info filtered)", logs.Len())
	}
	if !lc.Enabled(zapcore.ErrorLevel) || lc.Enabled(zapcore.InfoLevel) {
		t.Error("Enabled did not honor the min level")
	}

	// Check directly (nil in): a below-level entry stays nil; an at/above-level entry adds a core.
	if lc.Check(zapcore.Entry{Level: zapcore.InfoLevel}, nil) != nil {
		t.Error("below-level Check should return nil")
	}
	if lc.Check(zapcore.Entry{Level: zapcore.ErrorLevel}, nil) == nil {
		t.Error("at-level Check should return a checked entry")
	}
}

func TestNewAdaptsZapLogger(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	New(zap.New(core)).Info("adapted")
	if logs.Len() != 1 {
		t.Errorf("New-adapted logger recorded %d, want 1", logs.Len())
	}
}

func TestRedact(t *testing.T) {
	if Redact("") != "" {
		t.Error("empty stays empty")
	}
	if Redact("super-secret-token") != "[redacted]" {
		t.Error("non-empty secret must be masked")
	}
}

func TestNopLogger(t *testing.T) {
	// The nop logger must accept calls without panicking.
	l := Nop()
	l.Info("ignored", String("k", "v"))
	l.Error("ignored")
}

func TestSetupConsoleOnly(t *testing.T) {
	log, shutdown, err := Setup(context.Background(), Config{Service: "test", Level: "debug", Format: "console"})
	if err != nil || log == nil || shutdown == nil {
		t.Fatalf("setup returned nil (log-nil=%v shutdown-nil=%v err=%v)", log == nil, shutdown == nil, err)
	}
	log.Info("console-only line") // goes to stdout; must not panic
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("console-only shutdown err = %v", err)
	}
}

func TestSetupWithOTLPExporter(t *testing.T) {
	// A configured OTLP endpoint adds the OTel log core (lazy — no connection until flush).
	ctx := context.Background()
	log, shutdown, err := Setup(ctx, Config{
		Service: "test", Level: "info", Format: "json",
		OTLPEndpoint: "localhost:4318", OTLPInsecure: true,
	})
	if err != nil || log == nil {
		t.Fatalf("setup with OTLP: log=%v err=%v", log, err)
	}
	log.Info("dual-channel line") // enqueued to the OTel batch as well as the console
	// Shutdown flushes + closes the exporter within the deadline. Without a live collector the
	// flush export fails (connection refused) — which is fine: the point is that the OTel path
	// is wired and shutdown returns promptly rather than hanging.
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = shutdown(sctx); close(done) }()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("otlp shutdown hung")
	}

	// The secure (https) branch is also constructed without error (lazy — no dial here).
	secure, secureShutdown, err := Setup(ctx, Config{Service: "test", OTLPEndpoint: "localhost:4318"})
	if err != nil || secure == nil {
		t.Fatalf("setup secure OTLP: log=%v err=%v", secure == nil, err)
	}
	sctx2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancel2()
	_ = secureShutdown(sctx2)
}

func TestRequestLogger(t *testing.T) {
	log, logs := captured(zapcore.InfoLevel)
	handler := RequestLogger(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/publications", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get(CorrelationHeader) == "" {
		t.Error("correlation id not echoed on the response")
	}
	if logs.Len() != 1 {
		t.Fatalf("recorded %d, want 1", logs.Len())
	}
	m := logs.All()[0].ContextMap()
	if m["method"] != "POST" || m["path"] != "/publications" || m["status"] != int64(http.StatusCreated) {
		t.Errorf("request fields = %+v", m)
	}
	if m["correlation_id"] == "" {
		t.Error("correlation id not logged")
	}
}

func TestRequestLoggerPropagatesCorrelationID(t *testing.T) {
	log, logs := captured(zapcore.InfoLevel)
	// A handler that never writes a status → default 200 is captured.
	handler := RequestLogger(log)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(CorrelationHeader, "given-cid")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get(CorrelationHeader) != "given-cid" {
		t.Error("incoming correlation id should propagate")
	}
	if m := logs.All()[0].ContextMap(); m["correlation_id"] != "given-cid" || m["status"] != int64(http.StatusOK) {
		t.Errorf("fields = %+v", m)
	}
}
