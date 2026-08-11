package domain

import (
	"slices"
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
	// Summary is the winning source's short account of WHAT this vulnerability is, chosen by
	// the same precedence discipline as the headline but in an INDEPENDENT race: a source that
	// wins severity with no description must not blank the description another source supplied
	// (Red Hat routinely carries severity without prose while OSV carries the summary).
	//
	// Deliberately outside the trust field-groups: it is descriptive, no verdict consumes it,
	// and Grounding Verification anchors to the projection's facts, never to prose. Giving it
	// a trust class would imply something reads it to decide; nothing may.
	Summary        string
	SummarySource  string // which source won the summary (explainability, same rule as SeveritySource)
	AffectedRanges []string
	// Fixes are the remediations, each attributed to the package it applies to. This is the
	// authoritative form — use FixesFor to ask "what fixes MY component?".
	Fixes []FixedVersion
	// FixedVersions is the flat union of Fixes' versions, kept for wire compatibility and for
	// "is a fix published at all?" questions.
	//
	// It is DELIBERATELY not usable for a per-component decision: it is a union across every
	// package the CVE affects, so a version in it may belong to a different package entirely
	// (KN-FIX-1). Anything deciding about one component must go through Fixes/FixesFor.
	FixedVersions []string
	EPSS          float64
	KEV           bool
	ExploitPublic bool

	// Trust is tracked per field-group, not for the view as a whole (EDR-TRUST-01 T3).
	// A single view-level class would be actively wrong: one vendor VEX statement
	// (Asserted) on a card would drag the whole view down and incorrectly downgrade a
	// version-range verdict computed purely from Observed ranges. A conclusion inherits
	// the trust of the evidence *it* depended on, so each group carries its own.
	//
	// Each is **unset** when no proposal of that kind contributed. That is deliberate and
	// safe: value.MaxTrust treats an unset class as Inferred, so a consumer that folds one
	// in without checking degrades to the most conservative answer rather than silently
	// claiming Observed.
	HeadlineTrust value.TrustClass // class of the source that won the headline severity/CVSS
	RangeTrust    value.TrustClass // highest-risk class among sources contributing ranges / fixed versions
	SignalTrust   value.TrustClass // highest-risk class among sources contributing exploit signals

	Applicabilities []Applicability

	// CarrierProducts is the union of every flaw-describing source's opinion about WHICH product
	// carries this CVE (EDR-CORRELATION-01 D4). Empty means nobody has said — which classifies
	// every component as ClaimUnknown, i.e. treated as a carrier. Absence of evidence must never
	// hide a live vulnerability.
	CarrierProducts []string
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
func Reconcile(proposals []Proposal, prec Precedence, trust TrustPolicy) EnterpriseView {
	view := EnterpriseView{Severity: value.SeverityUnknown}

	var best headlineCandidate
	var bestSummary summaryCandidate
	rangeSet := map[string]struct{}{}
	fixSet := map[FixedVersion]struct{}{}
	carrierSet := map[string]struct{}{}
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
			if f.Summary != "" {
				sc := summaryCandidate{
					set: true, rank: prec.rankOf(p.source), observedAt: p.observedAt,
					source: p.source, text: f.Summary,
				}
				if sc.beats(bestSummary) {
					bestSummary = sc
				}
			}
			// Ranges and fixed versions are a union, so the group inherits the highest-risk
			// class among every source that contributed to it (T3).
			if len(f.AffectedRanges) > 0 || len(f.Fixes) > 0 {
				view.RangeTrust = foldTrust(view.RangeTrust, trust.ClassOf(p.source))
			}
			for _, rng := range f.AffectedRanges {
				rangeSet[rng] = struct{}{}
			}
			for _, fx := range f.Fixes {
				fixSet[fx] = struct{}{}
			}
			// A UNION, like ranges and fixes: several sources may each name a carrier, and a CVE
			// can genuinely affect more than one product. Union is also the fail-safe direction —
			// a carrier named by any source keeps its components classified as carriers.
			for _, cp := range f.CarrierProducts {
				if strings.TrimSpace(cp) != "" {
					carrierSet[cp] = struct{}{}
				}
			}
		case KindExploitSignal:
			s := p.exploitSignal
			view.KEV = view.KEV || s.KEV
			view.ExploitPublic = view.ExploitPublic || s.ExploitPublic
			view.SignalTrust = foldTrust(view.SignalTrust, trust.ClassOf(p.source))
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
		// The headline is winner-take-all, so it inherits exactly the winner's class —
		// not a fold across losing candidates that contributed nothing to it.
		view.HeadlineTrust = trust.ClassOf(best.source)
	}
	if bestSummary.set {
		view.Summary = bestSummary.text
		view.SummarySource = bestSummary.source
	}
	view.AffectedRanges = sortedKeys(rangeSet)
	view.CarrierProducts = sortedKeys(carrierSet)
	view.Fixes = sortedFixes(fixSet)
	view.FixedVersions = flatVersions(view.Fixes)
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

// summaryCandidate is a contender for the reconciled summary — the headline discipline
// (precedence, then recency) applied in its own race, since presence of prose and presence
// of a severity are independent per source. The trailing text/source keys only make the
// order total; they never override authority.
type summaryCandidate struct {
	set        bool
	rank       int
	observedAt time.Time
	source     string
	text       string
}

func (c summaryCandidate) beats(o summaryCandidate) bool {
	if !o.set {
		return true
	}
	if c.rank != o.rank {
		return c.rank < o.rank
	}
	if !c.observedAt.Equal(o.observedAt) {
		return c.observedAt.After(o.observedAt)
	}
	if c.source != o.source {
		return c.source < o.source
	}
	return c.text < o.text
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
		v.Summary != o.Summary || v.SummarySource != o.SummarySource ||
		v.EPSS != o.EPSS || v.KEV != o.KEV || v.ExploitPublic != o.ExploitPublic {
		return false
	}
	// A trust change is a view change: evidence getting weaker or stronger is exactly
	// what Governance re-evaluates on, so it must fire FaultlineEnriched (D8).
	if v.HeadlineTrust != o.HeadlineTrust || v.RangeTrust != o.RangeTrust || v.SignalTrust != o.SignalTrust {
		return false
	}
	return equalStrings(v.AffectedRanges, o.AffectedRanges) &&
		equalFixes(v.Fixes, o.Fixes) &&
		equalApplicabilities(v.Applicabilities, o.Applicabilities)
}

// foldTrust accumulates a field-group's trust across contributing sources. The first
// contributor seeds the group (an unset accumulator means "no evidence yet", which
// value.MaxTrust would otherwise read as Inferred); every later one folds in via the
// monotonic max.
func foldTrust(acc, c value.TrustClass) value.TrustClass {
	if acc == "" {
		return c
	}
	return value.MaxTrust(acc, c)
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

// FixesFor returns the fix versions attributed to a specific package.
//
// Only exactly-attributed fixes are returned: an unattributed one (Package "") is excluded, not
// treated as a wildcard. That is the whole point — a decision about one component must rest on
// evidence about THAT component, and "the source did not say which package" is not evidence
// about any of them. Callers that want everything published take FixedVersions instead, and must
// not decide with it.
func (v EnterpriseView) FixesFor(pkg string) []string {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return nil
	}
	// Package-specific fixes come FIRST, module-stream rebuilds after (KN-MODULE-1). A modular
	// advisory lists every RPM rebuilt in the stream, so a card can hold both a direct fix and a
	// stream rebuild for the same package — and "upgrade to the direct fix" is the better
	// instruction when one exists. Nothing is dropped: the stream rebuild IS valid remediation on
	// a modular system, and the fixed-verdict engine needs the full set to reason about backports.
	// Only the ORDER changes, which is what a consumer showing the first N reads.
	var direct, module []string
	for _, f := range v.Fixes {
		if !strings.EqualFold(strings.TrimSpace(f.Package), pkg) {
			continue
		}
		if value.IsRPMModuleStream(f.Version) {
			module = append(module, f.Version)
			continue
		}
		direct = append(direct, f.Version)
	}
	return append(direct, module...)
}

// sortedFixes orders the reconciled fix set deterministically (package, then version), so the
// same Proposals in any order yield byte-identical output.
func sortedFixes(set map[FixedVersion]struct{}) []FixedVersion {
	if len(set) == 0 {
		return nil
	}
	out := make([]FixedVersion, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// flatVersions derives the legacy flat list: every distinct version, sorted.
func flatVersions(fixes []FixedVersion) []string {
	if len(fixes) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, f := range fixes {
		seen[f.Version] = struct{}{}
	}
	return sortedKeys(seen)
}

// equalFixes compares two reconciled fix sets. slices.Equal rather than a hand-rolled loop
// because the element-wise branch is unreachable here: Fixes is a sorted set derived from an
// append-only union, so it grows monotonically and differing content always differs in length.
// A hand-rolled loop would carry a branch no test could reach honestly.
func equalFixes(a, b []FixedVersion) bool { return slices.Equal(a, b) }
