package vexfeed

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// ParseOSVFeed parses an OSV JSON feed (Alpine, Rocky, Wolfi).
func ParseOSVFeed(raw []byte, feed string) ([]domain.VendorVEXAssertion, error) {
	var entries []osvEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		var single osvEntry
		if err2 := json.Unmarshal(raw, &single); err2 != nil {
			return nil, fmt.Errorf("parse osv feed: %w", err)
		}
		entries = []osvEntry{single}
	}
	var out []domain.VendorVEXAssertion
	for _, entry := range entries {
		cves := entry.cveIDs()
		if len(cves) == 0 {
			// No canonical CVE anywhere (aliases/upstream/related/id). Keep the
			// advisory-keyed finding rather than dropping it, but it won't enrich.
			if id := domain.NormalizeCVEID(entry.ID); id != "" {
				cves = []string{id}
			} else {
				continue
			}
		}
		entryVector := entry.cvssVector()
		for _, affected := range entry.Affected {
			eco := affected.Package.Ecosystem
			name := affected.Package.Name
			severity := affected.DatabaseSpecific.severityWord()
			for _, r := range affected.Ranges {
				if r.Type != "ECOSYSTEM" && r.Type != "" {
					continue
				}
				introduced, fixed := r.bounds()
				// A distro advisory (e.g. an RLSA) bundles several CVEs; emit one
				// assertion per CVE so findings are canonical-CVE-keyed, not
				// advisory-keyed (which the CVSS/EPSS/KEV enrichment can't join).
				for _, cveID := range cves {
					out = append(out, domain.VendorVEXAssertion{
						AdvisoryID:  entry.ID,
						Feed:        feed,
						CVEID:       cveID,
						Ecosystem:   eco,
						PackageName: name,
						Status:      domain.VEXStatusAffected,
						Introduced:  introduced,
						Fixed:       fixed,
						Severity:    severity,
						CVSSVector:  entryVector,
					})
				}
			}
		}
	}
	return out, nil
}

type osvEntry struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Related  []string      `json:"related"`
	Upstream []string      `json:"upstream"`
	Affected []osvAffected `json:"affected"`
	Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// cvssVector returns the first CVSS vector in the entry's severity block, if any.
// The textual severity word comes from each affected entry's database_specific
// block (where distro OSV feeds put it).
func (e osvEntry) cvssVector() string {
	for _, s := range e.Severity {
		t := strings.ToUpper(s.Type)
		if (t == "CVSS_V3" || t == "CVSS_V4" || t == "CVSSV3") && strings.HasPrefix(s.Score, "CVSS:") {
			return s.Score
		}
	}
	return ""
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

func (d osvDatabaseSpecific) severityWord() string {
	return strings.ToLower(strings.TrimSpace(d.Severity))
}

// cveIDs returns every distinct canonical CVE referenced by the entry, scanning
// aliases, upstream, and related (distros differ: Alpine/GHSA put the CVE in
// aliases, Rocky/RLSA put it in upstream) plus the entry id itself. An advisory
// that bundles several CVEs yields all of them.
func (e osvEntry) cveIDs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		n := domain.NormalizeCVEID(id)
		if strings.HasPrefix(strings.ToUpper(n), "CVE-") && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, group := range [][]string{e.Aliases, e.Upstream, e.Related} {
		for _, id := range group {
			add(id)
		}
	}
	add(e.ID)
	return out
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges           []osvRange          `json:"ranges"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

func (r osvRange) bounds() (introduced, fixed string) {
	for _, ev := range r.Events {
		if ev.Introduced != "" {
			introduced = ev.Introduced
		}
		if ev.Fixed != "" {
			fixed = ev.Fixed
		}
	}
	return introduced, fixed
}
