package notify_test

import (
	"testing"

	"github.com/themis-project/themis/internal/adapter/notify"
)

func TestName(t *testing.T) {
	if notify.Name() != "notify" {
		t.Fatalf("Name() = %q, want notify", notify.Name())
	}
}
