package httpserver

import (
	"errors"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestNewLogger(t *testing.T) {
	logger, err := NewLogger("test")
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	if logger == nil {
		t.Fatal("expected logger")
	}
}

func TestNewLoggerWithLevel(t *testing.T) {
	logger, err := NewLoggerWithLevel("test", "debug")
	if err != nil {
		t.Fatalf("NewLoggerWithLevel() error = %v", err)
	}
	if !logger.Core().Enabled(zap.DebugLevel) {
		t.Fatal("expected debug level enabled")
	}
	for _, tc := range []struct {
		level string
		check zapcore.Level
	}{
		{"warn", zap.WarnLevel},
		{"error", zap.ErrorLevel},
		{"info", zap.InfoLevel},
		{"unknown", zap.InfoLevel},
	} {
		logger, err := NewLoggerWithLevel("test", tc.level)
		if err != nil {
			t.Fatalf("level %q: %v", tc.level, err)
		}
		if !logger.Core().Enabled(tc.check) {
			t.Fatalf("level %q: expected %v enabled", tc.level, tc.check)
		}
	}
}

func TestNewLoggerInvalidConfig(t *testing.T) {
	orig := buildZapLogger
	defer func() { buildZapLogger = orig }()
	buildZapLogger = func(zap.Config) (*zap.Logger, error) {
		return nil, errors.New("build failed")
	}

	_, err := NewLogger("test")
	if err == nil {
		t.Fatal("expected error for invalid logger config")
	}
}

func TestWithRequest(t *testing.T) {
	base, err := NewLogger("test")
	if err != nil {
		t.Fatal(err)
	}
	logger := WithRequest(base, "req-1", "prod-1", "proj-1")
	if logger == nil {
		t.Fatal("expected logger with request fields")
	}
	logger = WithRequest(base, "req-2", "", "")
	if logger == nil {
		t.Fatal("expected logger with request id only")
	}
}
