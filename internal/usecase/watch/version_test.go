package watch_test

import (
	"testing"

	"github.com/themis-project/themis/internal/usecase/watch"
)

func TestName(t *testing.T) {
	if watch.Name() != "watch" {
		t.Fatalf("Name() = %q, want watch", watch.Name())
	}
}
