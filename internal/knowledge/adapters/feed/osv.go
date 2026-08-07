package feed

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// osvRecord is the curated subset of an OSV record the ACL consumes. Language ecosystems key
// the CVE as the id or among the aliases (e.g. a GHSA id aliasing a CVE). Distro advisories
// (Red Hat / Rocky / Alma) are advisory-keyed instead — id is an "RHSA-…", aliases is null, and
// the addressed CVE(s) live in `upstream` — so the ACL must read that field or every distro
// record is dropped as "no canonical CVE" (BACKLOG: distro OSV correlation).
type osvRecord struct {
	ID               string        `json:"id"`
	Modified         string        `json:"modified"`
	Aliases          []string      `json:"aliases"`
	Upstream         []string      `json:"upstream"`
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
	// Package.Name is the association KN-FIX-1 was about. OSV states, per affected entry, WHICH
	// package a range and its fix apply to — and this struct used to decode only Ranges, throwing
	// the name away at parse time. Everything downstream then had a union it could not attribute.
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
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
	// Gather EVERY addressed CVE, not just the first: a distro advisory keys its CVEs in
	// `upstream` (id is an RHSA), and one advisory can fix several — a component the advisory
	// covers is affected by each until it is patched, so each must be carded.
	cves := allCVEs(append(append([]string{rec.ID}, rec.Aliases...), rec.Upstream...)...)
	if len(cves) == 0 {
		return nil, fmt.Errorf("feed: no canonical CVE in osv id/aliases/upstream")
	}
	at, err := parseObserved(rec.Modified)
	if err != nil {
		return nil, err
	}

	vector := ""
	// PICK the best vector rather than taking the first. OSV lists CVSS_V2, CVSS_V3 and CVSS_V4
	// entries side by side, so `Severity[0]` let whichever the feed happened to order first decide
	// the enterprise's severity — a v2 vector silently outranking a v3.1 one.
	vectors := make([]string, 0, len(rec.Severity))
	for _, sev := range rec.Severity {
		vectors = append(vectors, sev.Score) // OSV's `score` field holds the VECTOR string
	}
	vector = value.PreferredCVSSVector(vectors)

	// DERIVE the base score from the vector when OSV publishes no number. OSV carries the vector
	// in `severity[]` and the number only in a database-specific extension, so a record with a
	// vector and no extension landed severity=unknown / score=0 — and an unknown severity scores
	// zero, which sorts a real vulnerability to the bottom of a triage queue. Deriving from the
	// published formula is reproducible evidence, not a guess.
	score := rec.DatabaseSpecific.CVSSScore
	if score == 0 {
		score = value.BaseScoreFromVector(vector)
	}
	cvss, err := value.NewCVSS(score, vector)
	if err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}

	var ranges []string
	var fixes []domain.FixedVersion
	for _, aff := range rec.Affected {
		pkg := strings.TrimSpace(aff.Package.Name)
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if r := rangeString(ev.Introduced, ev.Fixed); r != "" {
					ranges = append(ranges, r)
				}
				if ev.Fixed != "" {
					// Paired with the package this affected-entry is about, so a consumer can ask
					// "what fixes MY component?" instead of guessing from a union.
					fixes = append(fixes, domain.FixedVersion{Package: pkg, Version: ev.Fixed})
				}
			}
		}
	}

	facts := domain.VulnFacts{
		Severity: severityFrom(rec.DatabaseSpecific.Severity, cvss), CVSS: cvss, AffectedRanges: ranges, Fixes: fixes,
	}
	out := make([]Translated, 0, len(cves))
	for _, cve := range cves {
		p, err := domain.NewVulnFactsProposal(a.Source(), at, facts)
		if err != nil {
			return nil, err
		}
		out = append(out, Translated{CVE: cve, Proposal: p})
	}
	return out, nil
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
