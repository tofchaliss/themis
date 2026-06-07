package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestName(t *testing.T) {
	if domain.Name() != "domain" {
		t.Fatalf("Name() = %q, want domain", domain.Name())
	}
}
