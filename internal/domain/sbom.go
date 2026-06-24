package domain

import "context"

// SBOM format discriminators used by the parser registry.
const (
	SBOMFormatCycloneDX = "cyclonedx"
	SBOMFormatSPDX      = "spdx"
	SBOMFormatTrivy     = "trivy"
)

// ParseStatus tracks parser outcomes aligned with ingestion lifecycle states.
type ParseStatus string

const (
	ParseStatusAccepted ParseStatus = "ACCEPTED"
	ParseStatusRejected ParseStatus = "REJECTED"
	ParseStatusFailed   ParseStatus = "FAILED"
)

// CanonicalComponent is a normalized package identity.
type CanonicalComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
	Licenses  []string
}

// CanonicalDependencyEdge is a normalized dependency relationship.
type CanonicalDependencyEdge struct {
	FromPURL         string
	ToPURL           string
	RelationshipType string
}

// CanonicalSBOM is the format-neutral normalized SBOM model.
//
// CR-9: scanner-reported vulnerabilities embedded in an uploaded SBOM/scan are
// NOT carried here. Themis is a re-correlator — findings are created by matching
// components against its own feeds, not by trusting the scanner's vuln list — so
// the previously-parsed-then-dropped vulnerability section has been removed
// rather than left as dead data.
type CanonicalSBOM struct {
	Format       string
	SpecVersion  string
	Components   []CanonicalComponent
	Dependencies []CanonicalDependencyEdge
	Warnings     []string
}

// ParseOutcome is returned by the parser registry to callers.
type ParseOutcome struct {
	Accepted         bool
	HTTPStatus       int
	Status           ParseStatus
	SBOM             CanonicalSBOM
	Message          string
	SupportedFormats []string
}

// SBOMAdapter normalizes a raw document into CanonicalSBOM.
type SBOMAdapter interface {
	Format() string
	Parse(ctx context.Context, raw []byte, specVersion string) (CanonicalSBOM, error)
}

// SupportedSBOMFormats lists registered parser formats.
func SupportedSBOMFormats() []string {
	return []string{SBOMFormatCycloneDX, SBOMFormatSPDX, SBOMFormatTrivy}
}
