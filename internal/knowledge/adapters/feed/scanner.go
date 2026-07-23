package feed

import (
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// scannerRecord is the curated per-vulnerability shape the scanner ACL consumes — one
// finding from an image vulnerability scan report (Trivy / Grype / …), normalized at the
// Evidence border (EDR-EVIDENCE-01 D4: standards-only; a scanner is a *producer*). The
// Scanner field is provenance detail; identity is the CVE.
type scannerRecord struct {
	CVE        string   `json:"cve"`
	ObservedAt string   `json:"observed_at"`
	Scanner    string   `json:"scanner"`
	Severity   string   `json:"severity"`
	CVSSScore  float64  `json:"cvss_score"`
	CVSSVector string   `json:"cvss_vector"`
	Affected   []string `json:"affected"`
	Fixed      []string `json:"fixed"`
}

// scannerACL translates a scanner-report finding into a **vuln-facts** Proposal
// (EDR-KNOWLEDGE-01 D5/D6). It is a source like any other: the proposal is **advisory**
// (CON-0002) and carries no special authority — because "scanner" is not in the
// reconciliation precedence's authoritative set, distro-authoritative / NVD facts always
// win a contested headline (D2). This realizes the deferred "scanner report as a source
// Proposal" decision without letting a scanner set truth.
type scannerACL struct{}

func (scannerACL) Source() string { return "scanner" }

func (a scannerACL) Translate(raw []byte) ([]Translated, error) {
	var rec scannerRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("scanner: invalid json: %w", err)
	}
	cve, err := firstCVE(rec.CVE)
	if err != nil {
		return nil, err
	}
	at, err := parseObserved(rec.ObservedAt)
	if err != nil {
		return nil, err
	}
	cvss, err := value.NewCVSS(rec.CVSSScore, rec.CVSSVector)
	if err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}
	p, err := domain.NewVulnFactsProposal(a.Source(), at, domain.VulnFacts{
		Severity:       severityFrom(rec.Severity, cvss),
		CVSS:           cvss,
		AffectedRanges: rec.Affected,
		FixedVersions:  rec.Fixed,
	})
	if err != nil {
		return nil, err
	}
	return []Translated{{CVE: cve, Proposal: p}}, nil
}
