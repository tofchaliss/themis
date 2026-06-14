package vexfeed

import (
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// EnrichmentMatcher adapts DefaultMatcher to the enrichment VendorMatcher port.
type EnrichmentMatcher struct {
	Inner DefaultMatcher
}

// Match implements enrichment.VendorMatcher.
func (m EnrichmentMatcher) Match(sbomPURL, cveID string, assertions []domain.VendorVEXAssertion) enrichment.VendorMatchResult {
	out := m.Inner.Match(sbomPURL, cveID, assertions)
	return enrichment.VendorMatchResult{
		Matched:         out.Matched,
		PURLMismatch:    out.PURLMismatch,
		MatchType:       out.MatchType,
		Status:          out.ResolvedStatus,
		Assertion:       out.Assertion,
		UpstreamVEXPURL: out.UpstreamVEXPURL,
	}
}
