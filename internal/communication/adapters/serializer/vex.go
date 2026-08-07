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
	Vulnerability openvexVuln      `json:"vulnerability"`
	Products      []openvexProduct `json:"products"`
	Status        string           `json:"status"`
	Justification string           `json:"justification,omitempty"`
	StatusNotes   string           `json:"status_notes,omitempty"`
}

// openvexProduct is an OpenVEX v0.2.0 Product: an identified thing the statement is about,
// optionally naming the components inside it the statement actually concerns.
//
// This was previously a bare string, which is not the shape the spec defines and is not what
// Themis's OWN VEX parser reads — so a published document fed back in yielded nothing (the C6
// round-trip mismatch). Products are objects; subcomponents are where the affected packages go.
type openvexProduct struct {
	ID            string             `json:"@id"`
	Subcomponents []openvexComponent `json:"subcomponents,omitempty"`
}

type openvexComponent struct {
	ID string `json:"@id"`
}

type openvexVuln struct {
	Name string `json:"name"`
}

// releaseIRI renders a release id as a resolvable identifier rather than a bare UUID.
//
// A consumer receiving `"products": [{"@id": "2859e949-…"}]` cannot resolve it to anything;
// OpenVEX expects an IRI (or a PURL) that identifies the product outside this document. The
// namespace matches the document's own `@id`, so both point at the same authority.
func releaseIRI(releaseID string) string {
	if releaseID == "" {
		return ""
	}
	return themisNamespace + "/release/" + releaseID
}

// themisNamespace is the identifier authority for products and documents this instance emits.
// A deployment fronting a real host would override it; it is deliberately one constant so the
// document @id and the product @id can never disagree about who is speaking.
const themisNamespace = "https://themis.example"

// Render serializes the artifact as OpenVEX. The VEX status is the presentation mapping of
// the Position's stance (never a reinterpretation).
func (OpenVEX) Render(art domain.Artifact) ([]byte, error) {
	// One product — the release — carrying the affected packages as subcomponents. This is the
	// distinction OpenVEX draws and Themis previously collapsed: the PRODUCT is what was
	// shipped, the SUBCOMPONENTS are the packages within it the statement is about. A consumer
	// needs both to decide whether a statement applies to them.
	product := openvexProduct{ID: releaseIRI(art.Lineage.ReleaseID)}
	for _, purl := range art.Lineage.Components {
		product.Subcomponents = append(product.Subcomponents, openvexComponent{ID: purl})
	}
	stmt := openvexStatement{
		Vulnerability: openvexVuln{Name: art.Lineage.CVE},
		Products:      []openvexProduct{product},
		Status:        art.Stance.VEXStatus(),
		StatusNotes:   art.Rationale,
	}
	// OpenVEX requires a justification for not_affected.
	if stmt.Status == "not_affected" {
		stmt.Justification = "vulnerable_code_not_in_execute_path"
	}
	doc := openvexDoc{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         themisNamespace + "/vex/" + art.Lineage.FaultlineID,
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
