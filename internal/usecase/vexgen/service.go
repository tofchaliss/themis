package vexgen

import (
	"context"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// Service exports VEX documents and coverage summaries.
type Service interface {
	ExportVEX(ctx context.Context, productID, version string, format domain.VEXExportFormat) ([]byte, error)
	ExportCoverage(ctx context.Context, productID, version string) (domain.VEXCoverageSummary, error)
}

// Handler implements VEX export use cases.
type Handler struct {
	Repo        domain.VEXExportRepository
	VendorVEX   enrichment.VendorAssertionReader
	VendorMatch enrichment.VendorMatcher
}

var _ Service = (*Handler)(nil)

// ExportVEX builds a standards-compliant VEX document for a product version.
func (h *Handler) ExportVEX(ctx context.Context, productID, version string, format domain.VEXExportFormat) ([]byte, error) {
	entries, err := h.buildEntries(ctx, productID, version)
	if err != nil {
		return nil, err
	}
	switch format {
	case domain.VEXExportFormatOpenVEX:
		return SerializeOpenVEX(entries)
	default:
		return SerializeCycloneDX(entries)
	}
}

// ExportCoverage aggregates upstream VEX coverage counts for a product version.
func (h *Handler) ExportCoverage(ctx context.Context, productID, version string) (domain.VEXCoverageSummary, error) {
	if err := h.ensureProductVersion(ctx, productID, version); err != nil {
		return domain.VEXCoverageSummary{}, err
	}
	pv, err := h.Repo.GetProductVersion(ctx, productID, version)
	if err != nil {
		return domain.VEXCoverageSummary{}, err
	}
	findings, err := h.Repo.ListFindingsForProductVersion(ctx, pv.ID)
	if err != nil {
		return domain.VEXCoverageSummary{}, err
	}
	var summary domain.VEXCoverageSummary
	for _, finding := range findings {
		switch finding.UpstreamVEXCoverage {
		case domain.UpstreamVEXCoverageCovered:
			summary.Covered++
		case domain.UpstreamVEXCoveragePURLMismatch:
			summary.PURLMismatch++
		default:
			summary.NotCovered++
		}
	}
	return summary, nil
}

func (h *Handler) buildEntries(ctx context.Context, productID, version string) ([]domain.VEXExportEntry, error) {
	if err := h.ensureProductVersion(ctx, productID, version); err != nil {
		return nil, err
	}
	pv, err := h.Repo.GetProductVersion(ctx, productID, version)
	if err != nil {
		return nil, err
	}
	findings, err := h.Repo.ListFindingsForProductVersion(ctx, pv.ID)
	if err != nil {
		return nil, err
	}

	assertionCache := map[string][]domain.VEXAssertionMatch{}
	vendorCache := map[string][]domain.VendorVEXAssertion{}
	entries := make([]domain.VEXExportEntry, 0, len(findings))

	for _, finding := range findings {
		assertions, ok := assertionCache[finding.ArtifactID]
		if !ok {
			assertions, err = h.Repo.ListAssertionsForArtifact(ctx, finding.ArtifactID)
			if err != nil {
				return nil, err
			}
			assertionCache[finding.ArtifactID] = assertions
		}
		key := assertionKey(finding.ComponentPURL, finding.CVEID)
		matches := filterAssertions(assertions, key)

		if h.VendorVEX != nil && h.VendorMatch != nil {
			vendorAssertions, ok := vendorCache[finding.CVEID]
			if !ok {
				vendorAssertions, err = h.VendorVEX.ListVendorAssertionsForCVE(ctx, finding.CVEID)
				if err != nil {
					return nil, err
				}
				vendorCache[finding.CVEID] = vendorAssertions
			}
			if len(vendorAssertions) > 0 {
				match := h.VendorMatch.Match(finding.ComponentPURL, finding.CVEID, vendorAssertions)
				if match.Matched {
					matches = append(matches, vendorAssertionMatch(finding, match))
				}
			}
		}

		winner := enrichment.PickWinningAssertion(matches)
		entry := entryFromFinding(finding, winner)
		entries = append(entries, entry)
	}
	return entries, nil
}

func (h *Handler) ensureProductVersion(ctx context.Context, productID, version string) error {
	exists, err := h.Repo.ProductExists(ctx, productID)
	if err != nil {
		return err
	}
	if !exists {
		return domain.ErrProductNotFound
	}
	if _, err := h.Repo.GetProductVersion(ctx, productID, version); err != nil {
		return err
	}
	return nil
}

func entryFromFinding(finding domain.VEXExportFinding, winner *domain.VEXAssertionMatch) domain.VEXExportEntry {
	status := finding.VEXStatus
	justification := finding.SuppressionReason
	source := ""
	if winner != nil {
		status = winner.Status
		justification = winner.Justification
		source = winner.Source
		if justification == "" {
			_, _, justification, _ = enrichment.ResolveEffectiveState(winner)
		}
	}
	if status == "" {
		status = domain.VEXStatusUnderInvestigation
	}
	return domain.VEXExportEntry{
		BOMRef:        finding.ComponentPURL,
		CVEID:         finding.CVEID,
		VEXStatus:     status,
		Justification: justification,
		RiskScore:     finding.RiskScore,
		EPSSScore:     finding.EPSSScore,
		KEVListed:     finding.KEVListed,
		BlastRadius:   int(finding.BlastRadiusScore * 100),
		Source:        source,
	}
}

func filterAssertions(assertions []domain.VEXAssertionMatch, key string) []domain.VEXAssertionMatch {
	var out []domain.VEXAssertionMatch
	for _, assertion := range assertions {
		if assertionKey(assertion.ComponentPURL, assertion.CVEID) == key {
			out = append(out, assertion)
		}
	}
	return out
}

func assertionKey(purl, cveID string) string {
	return purl + "|" + cveID
}

func vendorAssertionMatch(finding domain.VEXExportFinding, match enrichment.VendorMatchResult) domain.VEXAssertionMatch {
	status := match.Status
	if status == "" {
		status = match.Assertion.Status
	}
	return domain.VEXAssertionMatch{
		ComponentPURL: finding.ComponentPURL,
		CVEID:         finding.CVEID,
		Status:        status,
		Justification: match.Assertion.Justification,
		Source:        domain.VEXSourceUpstreamVendor,
		MatchType:     string(match.MatchType),
	}
}

// ParseExportFormat normalises format query values.
func ParseExportFormat(raw string) domain.VEXExportFormat {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(domain.VEXExportFormatOpenVEX), "application/openvex+json":
		return domain.VEXExportFormatOpenVEX
	default:
		return domain.VEXExportFormatCycloneDX
	}
}

// FormatFromAccept selects export format from Accept header.
func FormatFromAccept(accept string) domain.VEXExportFormat {
	if strings.Contains(strings.ToLower(accept), "openvex") {
		return domain.VEXExportFormatOpenVEX
	}
	return domain.VEXExportFormatCycloneDX
}

// ErrUnsupportedFormat indicates an unknown export format.
var ErrUnsupportedFormat = fmt.Errorf("unsupported vex export format")
