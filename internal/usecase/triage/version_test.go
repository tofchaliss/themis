package triage_test

import (
	"testing"

	"github.com/themis-project/themis/internal/usecase/triage"
)

func TestName(t *testing.T) {
	if triage.Name() != "triage" {
		t.Fatalf("Name() = %q, want triage", triage.Name())
	}
}
