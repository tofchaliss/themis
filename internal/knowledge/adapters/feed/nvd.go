package feed

import (
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// nvdRecord is the subset of an NVD CVE record the ACL consumes.
type nvdRecord struct {
	ID           string   `json:"id"`
	ObservedAt   string   `json:"observed_at"`
	BaseScore    float64  `json:"base_score"`
	VectorString string   `json:"vector_string"`
	BaseSeverity string   `json:"base_severity"`
	Affected     []string `json:"affected"`
	Fixed        []string `json:"fixed"`
}

// nvdACL translates NVD CVE records into vuln-facts Proposals.
type nvdACL struct{}

func (nvdACL) Source() string { return "nvd" }

func (a nvdACL) Translate(raw []byte) ([]Translated, error) {
	var rec nvdRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("nvd: invalid json: %w", err)
	}
	cve, err := firstCVE(rec.ID)
	if err != nil {
		return nil, err
	}
	at, err := parseObserved(rec.ObservedAt)
	if err != nil {
		return nil, err
	}
	cvss, err := value.NewCVSS(rec.BaseScore, rec.VectorString)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	p, err := domain.NewVulnFactsProposal(a.Source(), at, domain.VulnFacts{
		Severity: severityFrom(rec.BaseSeverity, cvss), CVSS: cvss, AffectedRanges: rec.Affected, FixedVersions: rec.Fixed,
	})
	if err != nil {
		return nil, err
	}
	return []Translated{{CVE: cve, Proposal: p}}, nil
}
