package store

import (
	"testing"
	"time"
)

func TestFirstTime(t *testing.T) {
	zero := time.Time{}
	a := time.Unix(100, 0)
	b := time.Unix(200, 0)

	if got := firstTime(nil, &zero, &a, &b); !got.Equal(a) {
		t.Fatalf("firstTime skipped nil/zero wrong: got %v, want %v", got, a)
	}
	if got := firstTime(&b, &a); !got.Equal(b) {
		t.Fatalf("firstTime should return first non-nil: got %v, want %v", got, b)
	}
	if got := firstTime(nil, &zero); !got.IsZero() {
		t.Fatalf("firstTime with only nil/zero should be zero, got %v", got)
	}
}
