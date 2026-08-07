// Package vex is Knowledge's anti-corruption parser for uploaded VEX documents (EDR-VEX-01
// D2): it turns a raw OpenVEX document into per-(CVE, package) applicability statements that
// the app folds as `applicability` Proposals. It parses only — honoring a statement for a
// release is Governance's decision (Proposal Before Truth).
package vex

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Statement is one applicability statement: a vendor's status for a (CVE, package) pair.
type Statement struct {
	CVE           string
	Package       string
	Status        string
	Justification string
}

type openVEXDoc struct {
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability json.RawMessage  `json:"vulnerability"`
	Products      []openVEXProduct `json:"products"`
	Status        string           `json:"status"`
	Justification string           `json:"justification"`
}

type openVEXProduct struct {
	ID            string             `json:"@id"`
	Subcomponents []openVEXComponent `json:"subcomponents"`
}

type openVEXComponent struct {
	ID string `json:"@id"`
}

// ParseOpenVEX parses an OpenVEX 0.2 document into per-(CVE, product) applicability
// statements. It skips any statement missing a CVE, a status, or a product id. The
// `vulnerability` field may be an object {"name": "CVE-..."} or a bare "CVE-..." string.
func ParseOpenVEX(raw []byte) ([]Statement, error) {
	var doc openVEXDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("vex: invalid OpenVEX json: %w", err)
	}
	var out []Statement
	for _, st := range doc.Statements {
		cve := vulnName(st.Vulnerability)
		status := strings.TrimSpace(st.Status)
		if cve == "" || status == "" {
			continue
		}
		for _, p := range st.Products {
			// SUBCOMPONENTS first, when present. OpenVEX puts the affected packages there and
			// the shipped thing in `@id`, so a document naming a release plus its packages must
			// yield a statement per PACKAGE — a statement keyed by the release identifier would
			// match no component in Knowledge and silently suppress nothing.
			matched := false
			for _, sub := range p.Subcomponents {
				if pkg := strings.TrimSpace(sub.ID); pkg != "" {
					out = append(out, Statement{CVE: cve, Package: pkg, Status: status, Justification: st.Justification})
					matched = true
				}
			}
			if matched {
				continue
			}
			// No subcomponents: fall back to the product id. Plenty of real-world VEX documents
			// put a PURL straight in `@id` with no subcomponents at all, and dropping those
			// would refuse valid third-party input to enforce a shape the spec does not require.
			if pkg := strings.TrimSpace(p.ID); pkg != "" {
				out = append(out, Statement{CVE: cve, Package: pkg, Status: status, Justification: st.Justification})
			}
		}
	}
	return out, nil
}

// vulnName extracts the CVE id from the OpenVEX `vulnerability` field, which may be an object
// {"name": "..."} or a bare string.
func vulnName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var obj struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && strings.TrimSpace(obj.Name) != "" {
		return strings.TrimSpace(obj.Name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return ""
}
