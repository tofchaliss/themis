package feed

import (
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// redhatRecord is the subset of a Red Hat Security Data record the ACL consumes. Red
// Hat severities (low/moderate/important/critical) fold to the canonical scale.
type redhatRecord struct {
	CVE        string `json:"cve"`
	ObservedAt string `json:"observed_at"`
	Severity   string `json:"severity"`
	CVSS3      struct {
		Score  float64 `json:"cvss3_base_score"`
		Vector string  `json:"cvss3_scoring_vector"`
	} `json:"cvss3"`
	AffectedPackages []string `json:"affected_packages"`
	FixedPackages    []string `json:"fixed_packages"`
}

// redhatACL translates Red Hat Security Data records into vuln-facts Proposals.
type redhatACL struct{}

func (redhatACL) Source() string { return "redhat" }

func (a redhatACL) Translate(raw []byte) ([]Translated, error) {
	var rec redhatRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("redhat: invalid json: %w", err)
	}
	cve, err := firstCVE(rec.CVE)
	if err != nil {
		return nil, err
	}
	at, err := parseObserved(rec.ObservedAt)
	if err != nil {
		return nil, err
	}
	cvss, err := value.NewCVSS(rec.CVSS3.Score, rec.CVSS3.Vector)
	if err != nil {
		return nil, fmt.Errorf("redhat: %w", err)
	}
	p, err := domain.NewVulnFactsProposal(a.Source(), at, domain.VulnFacts{
		Severity: severityFrom(rec.Severity, cvss), CVSS: cvss, AffectedRanges: rec.AffectedPackages, FixedVersions: rec.FixedPackages,
	})
	if err != nil {
		return nil, err
	}
	return []Translated{{CVE: cve, Proposal: p}}, nil
}
