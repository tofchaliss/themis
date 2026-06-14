package enrichment

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// VendorMatchResult is the outcome of four-phase upstream VEX matching.
type VendorMatchResult struct {
	Matched        bool
	PURLMismatch   bool
	MatchType      domain.VEXMatchType
	Status         string
	Assertion      domain.VendorVEXAssertion
	UpstreamVEXPURL string
}

// VendorMatcher applies upstream vendor VEX PURL matching (implemented in adapter/vexfeed).
type VendorMatcher interface {
	Match(sbomPURL, cveID string, assertions []domain.VendorVEXAssertion) VendorMatchResult
}

// VendorAssertionReader loads persisted upstream vendor assertions.
type VendorAssertionReader interface {
	ListVendorAssertionsForCVE(ctx context.Context, cveID string) ([]domain.VendorVEXAssertion, error)
}
