package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestAPIKeyPrefix(t *testing.T) {
	if got := domain.APIKeyPrefix("abcd1234deadbeef"); got != "abcd1234" {
		t.Fatalf("APIKeyPrefix(full) = %q, want abcd1234", got)
	}
	if got := domain.APIKeyPrefix("abcd1234"); got != "abcd1234" {
		t.Fatalf("APIKeyPrefix(exactly 8) = %q", got)
	}
	if got := domain.APIKeyPrefix("short"); got != "" {
		t.Fatalf("APIKeyPrefix(short) = %q, want empty", got)
	}
}
