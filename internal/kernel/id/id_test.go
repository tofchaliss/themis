package id_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/id"
)

func TestNew_UniqueNonEmpty(t *testing.T) {
	a := id.New()
	b := id.New()
	if a == "" || b == "" {
		t.Fatal("id.New returned an empty id")
	}
	if a == b {
		t.Errorf("id.New returned duplicate ids: %q", a)
	}
	if len(a) != 36 { // canonical UUID string length
		t.Errorf("id.New length = %d, want 36 (%q)", len(a), a)
	}
}

func TestSystemClock_Now(t *testing.T) {
	var c id.Clock = id.SystemClock{}
	before := time.Now().UTC().Add(-time.Second)
	got := c.Now()
	after := time.Now().UTC().Add(time.Second)
	if got.Before(before) || got.After(after) {
		t.Errorf("Now() = %v, want within [%v, %v]", got, before, after)
	}
	if got.Location() != time.UTC {
		t.Errorf("Now() location = %v, want UTC", got.Location())
	}
}
