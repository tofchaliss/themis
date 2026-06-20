package trust

import (
	"context"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// StubVerifier records trust status without performing cryptographic verification.
type StubVerifier struct{}

// Verify implements domain.SignatureVerifier.
func (StubVerifier) Verify(_ context.Context, artifact domain.RawArtifact) (domain.TrustResult, error) {
	result := domain.TrustResult{
		SignatureVerified: false,
		ChecksumSHA256:    checksumSHA256(artifact.RawDocument),
	}
	if strings.TrimSpace(artifact.Signature) == "" {
		result.Status = domain.TrustStatusUnsigned
		return result, nil
	}
	result.Status = domain.TrustStatusUnverified
	return result, nil
}
