package feed

import (
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// vexRecord is a vendor VEX document about one vulnerability, with a per-product
// applicability statement. Whether to honor "not_affected" for a given release is
// Governance's decision, not Knowledge's — the ACL only records the statement.
type vexRecord struct {
	Vulnerability string         `json:"vulnerability"`
	ObservedAt    string         `json:"observed_at"`
	Statements    []vexStatement `json:"statements"`
}

type vexStatement struct {
	Product       string `json:"product"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

// vexACL translates vendor VEX documents into applicability Proposals — one per
// statement.
type vexACL struct{}

func (vexACL) Source() string { return "vexfeed" }

func (a vexACL) Translate(raw []byte) ([]Translated, error) {
	var rec vexRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("vexfeed: invalid json: %w", err)
	}
	cve, err := firstCVE(rec.Vulnerability)
	if err != nil {
		return nil, err
	}
	at, err := parseObserved(rec.ObservedAt)
	if err != nil {
		return nil, err
	}
	if len(rec.Statements) == 0 {
		return nil, fmt.Errorf("vexfeed: no statements for %s", cve)
	}
	out := make([]Translated, 0, len(rec.Statements))
	for _, st := range rec.Statements {
		p, err := domain.NewApplicabilityProposal(a.Source(), at, domain.Applicability{
			Package: st.Product, Status: st.Status, Justification: st.Justification,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, Translated{CVE: cve, Proposal: p})
	}
	return out, nil
}
