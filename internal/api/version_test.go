package api_test

import (
	"testing"

	"github.com/themis-project/themis/internal/api"
)

func TestName(t *testing.T) {
	if api.Name() != "api" {
		t.Fatalf("Name() = %q, want api", api.Name())
	}
}
