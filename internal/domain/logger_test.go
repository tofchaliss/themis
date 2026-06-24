package domain

import (
	"errors"
	"testing"
)

func TestLogFieldHelpers(t *testing.T) {
	if f := LogString("k", "v"); f.Key != "k" || f.Value != "v" {
		t.Fatalf("LogString = %+v", f)
	}
	if f := LogInt("n", 5); f.Key != "n" || f.Value != 5 {
		t.Fatalf("LogInt = %+v", f)
	}
	if f := LogAny("a", []int{1}); f.Key != "a" {
		t.Fatalf("LogAny = %+v", f)
	}
	if f := LogErr(nil); f.Key != "error" || f.Value != "" {
		t.Fatalf("LogErr(nil) = %+v", f)
	}
	if f := LogErr(errors.New("boom")); f.Value != "boom" {
		t.Fatalf("LogErr = %+v", f)
	}
}

func TestNopLogger(t *testing.T) {
	var l Logger = NopLogger{}
	l.Debug("d", LogString("k", "v"))
	l.Info("i")
	l.Warn("w")
	l.Error("e", LogErr(errors.New("x")))
	if l.With(LogString("k", "v")) == nil {
		t.Fatal("With must return a logger")
	}
}

func TestLoggerOrNop(t *testing.T) {
	if _, ok := LoggerOrNop(nil).(NopLogger); !ok {
		t.Fatal("nil → NopLogger")
	}
	custom := NopLogger{}
	if got := LoggerOrNop(custom); got != Logger(custom) {
		t.Fatal("non-nil returned unchanged")
	}
}
