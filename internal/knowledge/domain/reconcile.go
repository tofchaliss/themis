package domain

import (
	"sort"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// EnterpriseView is the Faultline's reconciled, authoritative understanding, derived
// from its source Proposals by the precedence rule (D2). It is materialized state and
// is what Knowledge events fire on (D8). Every field is derived deterministically, so
// the same Proposals in any order yield the same view.
type EnterpriseView struct {
	Severity       value.Severity
	CVSS           value.CVSS
	SeveritySource string // which source won the headline severity (explainability, CON-0003)
	AffectedRanges []string
	FixedVersions  []string
	EPSS           float64
	KEV            bool
	ExploitPublic  bool
	Applicabilities []Applicability
}

// Precedence is the fixed, source-agnostic ranking policy that decides which source
// wins a contested headline field (D2). Earlier sources in the list have higher
// authority (distro-authoritative first, then NVD, then others). Sources not listed
// rank below all listed ones. The exact table is an app-layer policy
// (EDR-KNOWLEDGE-01 D2 open item); the domain provides only the mechanism.
type Precedence struct {
	order map[string]int
}

// NewPrecedence builds a Precedence from sources in descending authority order.
func NewPrecedence(rankedSources ...string) Precedence {
	order := make(map[string]int, len(rankedSources))
	for i, s := range rankedSources {
		order[strings.ToLower(s)] = i
	}
	return Precedence{order: order}
}

// rankOf returns the authority rank of a source (lower = higher authority). Unlisted
// sources share the lowest rank.
func (p Precedence) rankOf(source string) int {
	if r, ok := p.order[strings.ToLower(source)]; ok {
		return r
	}
	return len(p.order) + 1
}

// Reconcile folds the Proposals into an EnterpriseView using the precedence rule. It is
// pure and order-independent (the D2 determinism guarantee):
//   - headline severity/CVSS = chosen by a strict total order — highest authority
//     (precedence rank) first, then a source's more recent observation, then (only for
//     an otherwise-exact tie, e.g. one source reporting two severities at once) the
//     higher severity, then CVSS, then source name. Precedence is the primary rule;
//     the later keys only break ties deterministically (never a naive worst-case or
//     newest-wins over the whole card);
//   - affected ranges + fix versions = the sorted union across vuln-facts;
//   - KEV / public-exploit = logical-OR; EPSS = the latest observation (ties → higher);
//   - applicabilities = the sorted set of vendor VEX statements (held, not folded).
func Reconcile(proposals []Proposal, prec Precedence) EnterpriseView {
	view := EnterpriseView{Severity: value.SeverityUnknown}

	var best headlineCandidate
	rangeSet := map[string]struct{}{}
	fixSet := map[string]struct{}{}
	epssChosen := false
	var epssTime time.Time
	appSet := map[Applicability]struct{}{}

	for _, p := range proposals {
		switch p.kind {
		case KindVulnFacts:
			f := p.vulnFacts
			if f.Severity != value.SeverityUnknown {
				c := headlineCandidate{
					set: true, rank: prec.rankOf(p.source), observedAt: p.observedAt,
					severity: f.Severity, cvss: f.CVSS, source: p.source,
				}
				if c.beats(best) {
					best = c
				}
			}
			for _, rng := range f.AffectedRanges {
				rangeSet[rng] = struct{}{}
			}
			for _, fx := range f.FixedVersions {
				fixSet[fx] = struct{}{}
			}
		case KindExploitSignal:
			s := p.exploitSignal
			view.KEV = view.KEV || s.KEV
			view.ExploitPublic = view.ExploitPublic || s.ExploitPublic
			// EPSS: latest observation wins; equal timestamps → higher value (deterministic).
			if !epssChosen || p.observedAt.After(epssTime) ||
				(p.observedAt.Equal(epssTime) && s.EPSS > view.EPSS) {
				view.EPSS = s.EPSS
				epssTime = p.observedAt
				epssChosen = true
			}
		case KindApplicability:
			appSet[*p.applicability] = struct{}{}
		}
	}

	if best.set {
		view.Severity = best.severity
		view.CVSS = best.cvss
		view.SeveritySource = best.source
	}
	view.AffectedRanges = sortedKeys(rangeSet)
	view.FixedVersions = sortedKeys(fixSet)
	view.Applicabilities = sortedApplicabilities(appSet)
	return view
}

// headlineCandidate is a contender for the reconciled headline severity/CVSS, compared
// by a strict total order so the winner is independent of proposal order.
type headlineCandidate struct {
	set        bool
	rank       int
	observedAt time.Time
	severity   value.Severity
	cvss       value.CVSS
	source     string
}

// beats reports whether c should win the headline over the current best. The key,
// most-significant first: lower rank, newer observation, higher severity, higher CVSS,
// lower source name.
func (c headlineCandidate) beats(o headlineCandidate) bool {
	if !o.set {
		return true
	}
	if c.rank != o.rank {
		return c.rank < o.rank
	}
	if !c.observedAt.Equal(o.observedAt) {
		return c.observedAt.After(o.observedAt)
	}
	if cs, os := severityRank(c.severity), severityRank(o.severity); cs != os {
		return cs > os
	}
	if c.cvss.Score() != o.cvss.Score() {
		return c.cvss.Score() > o.cvss.Score()
	}
	return c.source < o.source
}

// severityRank orders severities from least to most severe for deterministic
// tiebreaking (not for headline selection — precedence decides that).
func severityRank(s value.Severity) int {
	switch s {
	case value.SeverityNone:
		return 1
	case value.SeverityLow:
		return 2
	case value.SeverityMedium:
		return 3
	case value.SeverityHigh:
		return 4
	case value.SeverityCritical:
		return 5
	default:
		return 0 // unknown
	}
}

func (v EnterpriseView) equal(o EnterpriseView) bool {
	if v.Severity != o.Severity || v.CVSS != o.CVSS || v.SeveritySource != o.SeveritySource ||
		v.EPSS != o.EPSS || v.KEV != o.KEV || v.ExploitPublic != o.ExploitPublic {
		return false
	}
	return equalStrings(v.AffectedRanges, o.AffectedRanges) &&
		equalStrings(v.FixedVersions, o.FixedVersions) &&
		equalApplicabilities(v.Applicabilities, o.Applicabilities)
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedApplicabilities(set map[Applicability]struct{}) []Applicability {
	if len(set) == 0 {
		return nil
	}
	out := make([]Applicability, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		if out[i].Status != out[j].Status {
			return out[i].Status < out[j].Status
		}
		return out[i].Justification < out[j].Justification
	})
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalApplicabilities(a, b []Applicability) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
