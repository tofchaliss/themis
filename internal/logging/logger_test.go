package logging

import (
	"errors"
	"testing"

	"go.uber.org/zap"
)

func TestNew(t *testing.T) {
	logger, err := New("test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if logger == nil {
		t.Fatal("expected logger")
	}
}

func TestNewInvalidConfig(t *testing.T) {
	orig := buildZapLogger
	defer func() { buildZapLogger = orig }()
	buildZapLogger = func(zap.Config) (*zap.Logger, error) {
		return nil, errors.New("build failed")
	}

	_, err := New("test")
	if err == nil {
		t.Fatal("expected error for invalid logger config")
	}
}

func TestWithRequest(t *testing.T) {
	base, err := New("test")
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
