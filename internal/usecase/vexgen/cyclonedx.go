package vexgen

import (
	"encoding/json"

	"github.com/themis-project/themis/internal/domain"
)

type cycloneDXDocument struct {
	BOMFormat       string                   `json:"bomFormat"`
	SpecVersion     string                   `json:"specVersion"`
	Version         int                      `json:"version"`
	Vulnerabilities []cycloneDXVulnerability `json:"vulnerabilities"`
}

type cycloneDXVulnerability struct {
	BOMRef        string            `json:"bom-ref"`
	ID            string            `json:"id"`
	Analysis      cycloneDXAnalysis `json:"analysis"`
	Ratings       []cycloneDXRating `json:"ratings,omitempty"`
	XThemisEPSS   *float64          `json:"x-themis-epss-score,omitempty"`
	XThemisKEV    *bool             `json:"x-themis-kev-listed,omitempty"`
	XThemisBlast  *int              `json:"x-themis-blast-radius,omitempty"`
	XThemisSource string            `json:"x-themis-vex-source,omitempty"`
}

type cycloneDXAnalysis struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type cycloneDXRating struct {
	Score  float64 `json:"score"`
	Method string  `json:"method"`
}

// SerializeCycloneDX encodes export entries as CycloneDX 1.5+ JSON.
func SerializeCycloneDX(entries []domain.VEXExportEntry) ([]byte, error) {
	doc := cycloneDXDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
	}
	for _, entry := range entries {
		vuln := cycloneDXVulnerability{
			BOMRef: entry.BOMRef,
			ID:     entry.CVEID,
			Analysis: cycloneDXAnalysis{
				State:  mapCycloneDXState(entry.VEXStatus),
				Detail: entry.Justification,
			},
			XThemisSource: entry.Source,
		}
		if entry.RiskScore > 0 {
			vuln.Ratings = []cycloneDXRating{{Score: float64(entry.RiskScore), Method: "other"}}
		}
		if entry.EPSSScore != nil {
			vuln.XThemisEPSS = entry.EPSSScore
		}
		if entry.KEVListed {
			kev := true
			vuln.XThemisKEV = &kev
		}
		if entry.BlastRadius > 0 {
			blast := entry.BlastRadius
			vuln.XThemisBlast = &blast
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, vuln)
	}
	return json.Marshal(doc)
}

func mapCycloneDXState(status string) string {
	switch status {
	case domain.VEXStatusNotAffected:
		return "not_affected"
	case domain.VEXStatusAffected:
		return "affected"
	case domain.VEXStatusFixed:
		return "resolved"
	case domain.VEXStatusUnderInvestigation:
		return "in_triage"
	default:
		return "in_triage"
	}
}
