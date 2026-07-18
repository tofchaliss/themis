package serializer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/communication/domain"
)

// CSAF renders an artifact as a minimal CSAF (Common Security Advisory Framework) VEX
// document (JSON) — the machine-readable advisory standard. Deterministic.
type CSAF struct{}

// Format returns "csaf".
func (CSAF) Format() string { return "csaf" }

type csafDoc struct {
	Document        csafMeta   `json:"document"`
	Vulnerabilities []csafVuln `json:"vulnerabilities"`
}

type csafMeta struct {
	Category  string `json:"category"`
	Title     string `json:"title"`
	Publisher string `json:"publisher"`
}

type csafVuln struct {
	CVE           string              `json:"cve"`
	ProductStatus map[string][]string `json:"product_status"`
	Notes         []csafNote          `json:"notes,omitempty"`
}

type csafNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
}

// Render serializes the artifact as CSAF. The product-status key is the CSAF category that
// corresponds to the Position's stance (same conclusion, CSAF vocabulary).
func (CSAF) Render(art domain.Artifact) ([]byte, error) {
	vuln := csafVuln{
		CVE:           art.Lineage.CVE,
		ProductStatus: map[string][]string{csafStatus(art.Stance): {art.Lineage.ReleaseID}},
	}
	if art.Rationale != "" {
		vuln.Notes = []csafNote{{Category: "description", Text: art.Rationale}}
	}
	doc := csafDoc{
		Document:        csafMeta{Category: "csaf_vex", Title: art.Title, Publisher: "Themis"},
		Vulnerabilities: []csafVuln{vuln},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// csafStatus maps the stance to a CSAF product_status key.
func csafStatus(s domain.Stance) string {
	switch s {
	case domain.StanceNotAffected:
		return "known_not_affected"
	case domain.StanceMitigated:
		return "fixed"
	case domain.StanceUnderInvestigation, domain.StanceDeferred:
		return "under_investigation"
	default: // affected, accepted_risk
		return "known_affected"
	}
}

// MarkdownAdvisory renders an artifact as a human-readable Markdown security advisory.
// Deterministic.
type MarkdownAdvisory struct{}

// Format returns "markdown".
func (MarkdownAdvisory) Format() string { return "markdown" }

// Render serializes the artifact as a Markdown advisory. The stated conclusion is the
// Position's stance phrase.
func (MarkdownAdvisory) Render(art domain.Artifact) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", art.Title)
	fmt.Fprintf(&b, "%s\n\n", art.Summary)
	fmt.Fprintf(&b, "- **CVE:** %s\n", fallback(art.Lineage.CVE, "unspecified"))
	fmt.Fprintf(&b, "- **Release:** %s\n", fallback(art.Lineage.ReleaseID, "unspecified"))
	fmt.Fprintf(&b, "- **Status:** %s\n", art.Stance.Phrase())
	if art.Rationale != "" {
		fmt.Fprintf(&b, "\n## Rationale\n\n%s\n", art.Rationale)
	}
	return []byte(b.String()), nil
}

func fallback(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
