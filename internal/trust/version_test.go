package trust_test

import (
	"testing"

	"github.com/themis-project/themis/internal/trust"
)

func TestName(t *testing.T) {
	if trust.Name() != "trust" {
		t.Fatalf("Name() = %q, want trust", trust.Name())
	}
}
