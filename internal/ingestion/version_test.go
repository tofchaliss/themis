package ingestion_test

import (
	"testing"

	"github.com/themis-project/themis/internal/ingestion"
)

func TestName(t *testing.T) {
	if ingestion.Name() != "ingestion" {
		t.Fatalf("Name() = %q, want ingestion", ingestion.Name())
	}
}
