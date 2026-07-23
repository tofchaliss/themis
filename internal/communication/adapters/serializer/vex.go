package serializer

import (
	"encoding/json"

	"github.com/themis-project/themis/internal/communication/domain"
)

// OpenVEX renders an artifact as an OpenVEX document (JSON). Deterministic: no wall-clock
// fields, so re-rendering a given Position version yields identical bytes.
type OpenVEX struct{}

// Format returns "openvex".
func (OpenVEX) Format() string { return "openvex" }

type openvexDoc struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Version    int                `json:"version"`
	Statements []openvexStatement `json:"statements"`
}

type openvexStatement struct {
	Vulnerability openvexVuln `json:"vulnerability"`
	Products      []string    `json:"products"`
	Status        string      `json:"status"`
	Justification string      `json:"justification,omitempty"`
	StatusNotes   string      `json:"status_notes,omitempty"`
}

type openvexVuln struct {
	Name string `json:"name"`
}

// Render serializes the artifact as OpenVEX. The VEX status is the presentation mapping of
// the Position's stance (never a reinterpretation).
func (OpenVEX) Render(art domain.Artifact) ([]byte, error) {
	stmt := openvexStatement{
		Vulnerability: openvexVuln{Name: art.Lineage.CVE},
		Products:      []string{art.Lineage.ReleaseID},
		Status:        art.Stance.VEXStatus(),
		StatusNotes:   art.Rationale,
	}
	// OpenVEX requires a justification for not_affected.
	if stmt.Status == "not_affected" {
		stmt.Justification = "vulnerable_code_not_in_execute_path"
	}
	doc := openvexDoc{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         "https://themis.example/vex/" + art.Lineage.FaultlineID,
		Author:     "Themis",
		Version:    art.PositionVersion,
		Statements: []openvexStatement{stmt},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// CycloneDXVEX renders an artifact as a CycloneDX VEX (a minimal BOM carrying the
// vulnerability analysis). Deterministic.
type CycloneDXVEX struct{}

// Format returns "cyclonedx-vex".
func (CycloneDXVEX) Format() string { return "cyclonedx-vex" }

type cdxDoc struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxVulnerability struct {
	ID       string      `json:"id"`
	Analysis cdxAnalysis `json:"analysis"`
	Affects  []cdxAffect `json:"affects"`
}

type cdxAnalysis struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

// Render serializes the artifact as CycloneDX VEX.
func (CycloneDXVEX) Render(art domain.Artifact) ([]byte, error) {
	doc := cdxDoc{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Vulnerabilities: []cdxVulnerability{{
			ID:       art.Lineage.CVE,
			Analysis: cdxAnalysis{State: art.Stance.VEXStatus(), Detail: art.Rationale},
			Affects:  []cdxAffect{{Ref: art.Lineage.ReleaseID}},
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}
