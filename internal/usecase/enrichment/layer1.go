package enrichment

import (
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// Layer1Input is the signal set evaluated by deterministic Layer 1 rules.
type Layer1Input struct {
	CVSSScore     float64
	EPSSScore     *float64
	KEVListed     bool
	ExploitPublic bool
}

// ComputeDeterministicLevel applies the Phase 2a Layer 1 rule table (first match wins).
func ComputeDeterministicLevel(in Layer1Input) domain.DeterministicLevel {
	cvss := in.CVSSScore
	epss := epssValue(in.EPSSScore)

	if cvss >= 9.0 && in.KEVListed {
		return domain.DeterministicLevelCritical
	}
	if cvss >= 9.0 && in.ExploitPublic {
		return domain.DeterministicLevelHighPlus
	}
	if in.KEVListed && cvss < 9.0 {
		return domain.DeterministicLevelHigh
	}
	if epss >= 0.5 && cvss >= 7.0 && !in.KEVListed && !in.ExploitPublic {
		return domain.DeterministicLevelElevated
	}
	if cvss >= 9.0 {
		return domain.DeterministicLevelHigh
	}
	return domain.DeterministicLevelInformational
}

// ResolveCVSSScore returns the CVSS score for Layer 1, falling back from severity when absent.
func ResolveCVSSScore(finding domain.EnrichmentFinding) float64 {
	if finding.CVSSScore > 0 {
		return finding.CVSSScore
	}
	return CVSSFromSeverity(finding.RawSeverity)
}

// CVSSFromSeverity maps catalog severity labels to representative CVSS scores.
func CVSSFromSeverity(severity string) float64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 9.0
	case "high":
		return 7.0
	case "medium":
		return 4.0
	case "low":
		return 1.0
	default:
		return 0
	}
}

func epssValue(score *float64) float64 {
	if score == nil {
		return 0
	}
	return *score
}

func layer3Enricher(h *Handler) Layer3Enricher {
	if h.Layer3 != nil {
		return h.Layer3
	}
	return NoOpLayer3{}
}
