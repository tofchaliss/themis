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
	ID       string `json:"id"`
	Modified string `json:"modified"`
	// Summary/Details are OSV's description of the flaw. Both were delivered on every record
	// and parsed by nothing — the reason no screen could say what a CVE was about.
	Summary          string        `json:"summary"`
	Details          string        `json:"details"`
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
		Events []osvEvent `json:"events"`
	} `json:"ranges"`
}

// osvEvent is one entry of an OSV range's ordered event list.
type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
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
	var carriers []string
	for _, aff := range rec.Affected {
		pkg := strings.TrimSpace(aff.Package.Name)
		// A NON-DISTRO ecosystem entry names the project the flaw lives in, so its package IS a
		// carrier (EDR-CORRELATION-01 D4). A distro entry does not: an RLSA/RHSA lists every RPM
		// rebuilt by one advisory, and reading that list as N vulnerability claims is the whole
		// of CORR-1. Measured: a genuine PyYAML CVE named 23 packages, a CPython one named 62 —
		// breadth cannot tell them apart, so the ECOSYSTEM has to.
		if pkg != "" && !isDistroEcosystem(aff.Package.Ecosystem) {
			carriers = append(carriers, pkg)
		}
		for _, rng := range aff.Ranges {
			// OSV writes a range as an ORDERED event list — `{introduced: 0}, {fixed: 1.4.3}` — not
			// as pairs. Read one event at a time, this came out as two rules, `>=0` and `<1.4.3`,
			// OR'd together; and a lone `>=0` matches every version ever written, so no Go card
			// could ever be provably out of range (measured 2026-10-14: 330 stdlib Findings on
			// Go 1.27.1 untouched by the KN-GO-2 pass). Pair each introduced with the bound that
			// FOLLOWS it; an introduced with no following bound is genuinely open-ended.
			ranges = append(ranges, pairedRanges(rng.Events)...)
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					// Paired with the package this affected-entry is about, so a consumer can ask
					// "what fixes MY component?" instead of guessing from a union — and with the
					// entry's canonical ecosystem, so a Rocky bound never answers for an Alpine
					// component or vice versa (KN-FIX-3).
					fixes = append(fixes, domain.FixedVersion{
						Package: pkg, Version: ev.Fixed,
						Ecosystem: value.CanonicalEcosystem(aff.Package.Ecosystem),
					})
				}
			}
		}
	}

	facts := domain.VulnFacts{
		Summary:  osvSummary(rec),
		Severity: severityFrom(rec.DatabaseSpecific.Severity, cvss), CVSS: cvss, AffectedRanges: ranges, Fixes: fixes,
		CarrierProducts: carriers,
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

// osvSummary picks the short description: OSV's summary is written as a one-liner; when a
// record carries only details (long markdown), the first paragraph stands in. Either way the
// domain cap bounds what is stored — details can run to pages.
func osvSummary(rec osvRecord) string {
	if s := strings.TrimSpace(rec.Summary); s != "" {
		return domain.TruncateSummary(s)
	}
	d := strings.TrimSpace(rec.Details)
	if d == "" {
		return ""
	}
	if i := strings.Index(d, "\n\n"); i > 0 {
		d = d[:i]
	}
	return domain.TruncateSummary(d)
}

// distroEcosystems are OSV ecosystems whose records describe a SHIPMENT rather than a flaw. Their
// package lists are rebuild scope, so they cannot name a carrier (EDR-CORRELATION-01 D1/D4).
//
// Matched by prefix because OSV qualifies these with a release — `Rocky Linux:8`, `Red Hat:rhel_8`,
// `Debian:12`, `Alpine:v3.19`.
var distroEcosystems = []string{
	"rocky", "red hat", "redhat", "almalinux", "alma", "alpine", "debian", "ubuntu", "suse",
	"opensuse", "mageia", "photon", "chainguard", "wolfi", "oracle", "rhel", "centos",
}

// isDistroEcosystem reports whether an OSV ecosystem describes a distribution's shipment.
func isDistroEcosystem(eco string) bool {
	e := strings.ToLower(strings.TrimSpace(eco))
	if e == "" {
		return true // unknown provenance: assume shipment, which never INVENTS a carrier
	}
	for _, d := range distroEcosystems {
		if strings.HasPrefix(e, d) {
			return true
		}
	}
	return false
}

// pairedRanges walks an OSV event list in order and renders one rule per affected interval:
// `>=introduced,<fixed`, `>=introduced,<=last_affected`, `>=introduced` when nothing closes it,
// and `<fixed` / `<=last_affected` for a bound with no opening (a shape OSV does not emit, kept
// so a malformed record still yields the safe, wider rule).
func pairedRanges(events []osvEvent) []string {
	var out []string
	open := ""
	hasOpen := false
	flush := func(upper string) {
		switch {
		case hasOpen && upper != "":
			out = append(out, fmt.Sprintf(">=%s,%s", open, upper))
		case hasOpen:
			out = append(out, fmt.Sprintf(">=%s", open))
		case upper != "":
			out = append(out, upper)
		}
		open, hasOpen = "", false
	}
	for _, ev := range events {
		if ev.Introduced != "" {
			if hasOpen {
				flush("") // two introduceds in a row: the first interval never closed
			}
			open, hasOpen = ev.Introduced, true
		}
		if ev.Fixed != "" {
			flush("<" + ev.Fixed)
		} else if ev.LastAffected != "" {
			flush("<=" + ev.LastAffected)
		}
	}
	if hasOpen {
		flush("")
	}
	return out
}
