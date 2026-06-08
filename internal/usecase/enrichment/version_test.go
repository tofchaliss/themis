package enrichment_test

import (
	"testing"

	"github.com/themis-project/themis/internal/usecase/enrichment"
)

func TestName(t *testing.T) {
	if enrichment.Name() != "enrichment" {
		t.Fatalf("Name() = %q, want enrichment", enrichment.Name())
	}
}
