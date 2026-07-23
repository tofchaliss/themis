package feed

import (
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// osvRecord is the curated subset of an OSV record the ACL consumes. OSV carries the
// CVE as its id or among its aliases (e.g. a GHSA id aliasing a CVE).
type osvRecord struct {
	ID               string        `json:"id"`
	Modified         string        `json:"modified"`
	Aliases          []string      `json:"aliases"`
	Severity         []osvSeverity `json:"severity"`
	Affected         []osvAffected `json:"affected"`
	DatabaseSpecific struct {
		Severity  string  `json:"severity"`
		CVSSScore float64 `json:"cvss_score"`
	} `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`  // e.g. CVSS_V3
	Score string `json:"score"` // the CVSS vector string
}

type osvAffected struct {
	Ranges []struct {
		Events []struct {
			Introduced string `json:"introduced"`
			Fixed      string `json:"fixed"`
		} `json:"events"`
	} `json:"ranges"`
}

// osvACL translates OSV records into vuln-facts Proposals.
type osvACL struct{}

func (osvACL) Source() string { return "osv" }

func (a osvACL) Translate(raw []byte) ([]Translated, error) {
	var rec osvRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("osv: invalid json: %w", err)
	}
	cve, err := firstCVE(append([]string{rec.ID}, rec.Aliases...)...)
	if err != nil {
		return nil, err
	}
	at, err := parseObserved(rec.Modified)
	if err != nil {
		return nil, err
	}

	vector := ""
	if len(rec.Severity) > 0 {
		vector = rec.Severity[0].Score
	}
	cvss, err := value.NewCVSS(rec.DatabaseSpecific.CVSSScore, vector)
	if err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}

	var ranges, fixes []string
	for _, aff := range rec.Affected {
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if r := rangeString(ev.Introduced, ev.Fixed); r != "" {
					ranges = append(ranges, r)
				}
				if ev.Fixed != "" {
					fixes = append(fixes, ev.Fixed)
				}
			}
		}
	}

	p, err := domain.NewVulnFactsProposal(a.Source(), at, domain.VulnFacts{
		Severity: severityFrom(rec.DatabaseSpecific.Severity, cvss), CVSS: cvss, AffectedRanges: ranges, FixedVersions: fixes,
	})
	if err != nil {
		return nil, err
	}
	return []Translated{{CVE: cve, Proposal: p}}, nil
}

// rangeString renders an OSV introduced/fixed event pair as a human-readable range.
func rangeString(introduced, fixed string) string {
	switch {
	case introduced != "" && fixed != "":
		return fmt.Sprintf(">=%s,<%s", introduced, fixed)
	case introduced != "":
		return fmt.Sprintf(">=%s", introduced)
	case fixed != "":
		return fmt.Sprintf("<%s", fixed)
	default:
		return ""
	}
}
