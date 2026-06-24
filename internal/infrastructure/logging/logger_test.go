package logging

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/themis-project/themis/internal/domain"
)

func TestNewLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "", "bogus"} {
		l, err := New("themis", level)
		if err != nil {
			t.Fatalf("New(%q) error = %v", level, err)
		}
		if l.Zap() == nil {
			t.Fatalf("New(%q) nil zap", level)
		}
	}
}

func TestZapLoggerEmitsAllLevels(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	base := zap.New(core)
	var l domain.Logger = NewFromZap(base)

	l.Debug("d", domain.LogString("k", "v"))
	l.Info("i", domain.LogInt("n", 1))
	l.Warn("w")
	l.Error("e", domain.LogErr(nil))
	l.With(domain.LogString("component", "x")).Info("child")

	entries := logs.All()
	if len(entries) != 5 {
		t.Fatalf("want 5 log entries, got %d", len(entries))
	}
	if entries[0].Message != "d" || entries[0].Level != zapcore.DebugLevel {
		t.Fatalf("debug entry = %+v", entries[0])
	}
	// The child logger carries the bound field.
	child := entries[4]
	if child.Message != "child" {
		t.Fatalf("child message = %q", child.Message)
	}
	found := false
	for _, f := range child.Context {
		if f.Key == "component" {
			found = true
		}
	}
	if !found {
		t.Fatal("With() field not bound on child logger")
	}
}
