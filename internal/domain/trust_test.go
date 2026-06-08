package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestTrustStatusAndPolicyConstants(t *testing.T) {
	statuses := []domain.TrustStatus{
		domain.TrustStatusVerified,
		domain.TrustStatusUnverified,
		domain.TrustStatusUnsigned,
		domain.TrustStatusFailed,
	}
	for _, status := range statuses {
		if status == "" {
			t.Fatal("expected non-empty trust status")
		}
	}

	policies := []domain.TrustPolicy{
		domain.TrustPolicyStrict,
		domain.TrustPolicyStandard,
		domain.TrustPolicyPermissive,
	}
	for _, policy := range policies {
		if policy == "" {
			t.Fatal("expected non-empty trust policy")
		}
	}
}
