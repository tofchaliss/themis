package parser

import (
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// InspectCanonicalSBOM reads canonical model fields for validation and diagnostics.
func InspectCanonicalSBOM(sbom domain.CanonicalSBOM) map[string]int {
	counts := map[string]int{
		"components":      len(sbom.Components),
		"dependencies":    len(sbom.Dependencies),
		"vulnerabilities": len(sbom.Vulnerabilities),
		"warnings":        len(sbom.Warnings),
	}
	_ = sbom.Format + sbom.SpecVersion
	for _, component := range sbom.Components {
		_ = component.PURL + component.Name + component.Version + component.Ecosystem + strings.Join(component.Licenses, ",")
	}
	for _, edge := range sbom.Dependencies {
		_ = edge.FromPURL + edge.ToPURL + edge.RelationshipType
	}
	for _, vuln := range sbom.Vulnerabilities {
		_ = vuln.CVEID + vuln.Severity + vuln.CVSSVector + strings.Join(vuln.AffectedPURLs, ",") + strings.Join(vuln.FixVersions, ",")
		_ = vuln.CVSSScore
	}
	for _, warning := range sbom.Warnings {
		_ = warning
	}
	return counts
}
