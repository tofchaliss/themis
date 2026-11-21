package domain

import (
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Applicability policy, context order and temporal policy for CVSS selection
// (EDR-SCORING-01 4.1 steps 2-3 and 6.2, 4.3, 4.4). Policy version ScoreApplicabilityPolicyVersion.

// applyResult is step 2's outcome plus what the context named, which step 3 needs.
type applyResult struct {
	result        Applicability
	platformNamed bool
	packageNamed  bool
}

// applyContext reads an effective context against a component. A context is a comma-separated
// list of items (a CPE, a product name, "vendor:product:package" or "ecosystem:package").
//
//   - A CPE whose product scope can be placed (family + major) is compared with the component's
//     own scope: same family and major applies, a known different one does not apply, and a
//     component that cannot be placed leaves it unresolved.
//   - Any other item applies when one of its parts equals the component's name or source
//     package. A single ASSERTED package that names another package does not apply (the
//     publication itself said which package it is for); an inherited list that does not name
//     the component stays unresolved, because a product list is not a statement about every
//     package.
//
// Any applying item makes the context apply; otherwise any unresolved item keeps it unresolved;
// only a context whose every item is known not to apply is does_not_apply. An empty context is
// unresolved: missing is never read as "covers everything" or as "covers nothing".
func applyContext(ctx string, asserted bool, comp ScoreComponent, family string) applyResult {
	items := splitContext(ctx)
	out := applyResult{result: Unresolved}
	if len(items) == 0 {
		return out
	}
	applies, unresolved := 0, 0
	compScope := value.ScopeFromComponent(comp.PURL, comp.Version)
	for _, item := range items {
		if strings.HasPrefix(strings.ToLower(item), "cpe:") {
			if vs := value.ScopeFromCPE(item); vs.Known() {
				if family != "" && vs.Family == family {
					out.platformNamed = true
				}
				switch value.MatchScope(vs, compScope) {
				case value.ScopeApplicable:
					applies++
				case value.ScopeNotApplicable:
				default:
					unresolved++
				}
				continue
			}
			if nameMatches(cpeProduct(item), comp) {
				applies++
				out.packageNamed = true
			} else {
				unresolved++
			}
			continue
		}
		matched := false
		for _, part := range strings.Split(item, ":") {
			if nameMatches(part, comp) {
				matched = true
			}
		}
		if asserted && len(items) == 1 {
			// The publication itself said what it is for: a different ecosystem or package is
			// a known mismatch; a bare ecosystem is too broad to decide.
			node, compEco := nodeOf(NormaliseScoreContext(item)), value.CanonicalEcosystem(purlType(comp.PURL))
			switch {
			case node.level == 1 && node.family == compEco:
				unresolved++
			case node.level == 1, node.family != "" && node.family != compEco:
			case matched:
				applies++
				out.packageNamed = true
			}
			continue
		}
		if matched {
			applies++
			out.packageNamed = true
		} else {
			unresolved++
		}
	}
	switch {
	case applies > 0:
		out.result = Applies
	case unresolved > 0:
		out.result = Unresolved
	default:
		out.result = DoesNotApply
	}
	return out
}

// purlType is the type segment of a purl ("rpm" in pkg:rpm/...), or "".
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	t, _, _ := strings.Cut(rest, "/")
	return t
}

func splitContext(ctx string) []string {
	var out []string
	for _, item := range strings.Split(ctx, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func nameMatches(s string, comp ScoreComponent) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, n := range []string{comp.Name, comp.SourcePackage, purlName(comp.PURL)} {
		if n != "" && strings.EqualFold(n, s) {
			return true
		}
	}
	return false
}

// cpeProduct returns the product field of a CPE 2.2 URI or 2.3 string, or "".
func cpeProduct(cpe string) string {
	c := strings.ToLower(strings.TrimSpace(cpe))
	switch {
	case strings.HasPrefix(c, "cpe:2.3:"):
		c = c[len("cpe:2.3:"):]
	case strings.HasPrefix(c, "cpe:/"):
		c = c[len("cpe:/"):]
	default:
		return ""
	}
	f := strings.Split(c, ":")
	if len(f) < 3 {
		return ""
	}
	return f[2]
}

// NormaliseScoreContext folds case and space and canonicalises the ecosystem of an
// "ecosystem:package" context, so two spellings of one context compare equal.
func NormaliseScoreContext(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if eco, pkg, ok := strings.Cut(s, ":"); ok && !strings.HasPrefix(s, "cpe:") && !strings.Contains(s, ",") {
		return value.CanonicalEcosystem(eco) + ":" + pkg
	}
	return s
}

// ecosystemTokens are the single-word contexts the context order reads as an ecosystem or
// family (part of ScoreApplicabilityPolicyVersion). Any other single word is a product.
var ecosystemTokens = map[string]bool{
	"npm": true, "pypi": true, "maven": true, "golang": true, "go": true, "cargo": true, "gem": true,
	"nuget": true, "composer": true, "hex": true, "pub": true, "swift": true, "cocoapods": true,
	"conan": true, "rpm": true, "apk": true, "deb": true, "alpine": true, "debian": true,
	"ubuntu": true, "rhel": true, "rocky": true, "alma": true, "almalinux": true, "centos": true,
	"fedora": true,
}

// contextNode places one normalised context in the context order.
type contextNode struct {
	level  int // 0 unstated, 1 ecosystem / family, 2 package, 3 opaque (a list)
	family string
	pkg    string
}

func nodeOf(ctx string) contextNode {
	switch {
	case ctx == "":
		return contextNode{}
	case strings.Contains(ctx, ","):
		return contextNode{level: 3}
	case strings.HasPrefix(ctx, "cpe:"):
		if vs := value.ScopeFromCPE(ctx); vs.Known() {
			return contextNode{level: 1, family: "cpe/" + vs.Family + "/" + vs.Major}
		}
		return contextNode{level: 2, pkg: cpeProduct(ctx)}
	}
	if eco, pkg, ok := strings.Cut(ctx, ":"); ok {
		return contextNode{level: 2, family: value.CanonicalEcosystem(eco), pkg: pkg}
	}
	if ecosystemTokens[ctx] {
		return contextNode{level: 1, family: value.CanonicalEcosystem(ctx)}
	}
	return contextNode{level: 2, pkg: ctx}
}

// moreSpecific reports whether context a is strictly more specific than context b under the
// context order: package P in E is more specific than E, E than unstated. Contexts where neither
// contains the other are incomparable and never ranked (D21).
func moreSpecific(a, b string) bool {
	if a == b {
		return false
	}
	na, nb := nodeOf(a), nodeOf(b)
	switch {
	case nb.level == 0:
		return true
	case nb.level == 1 && na.level == 2:
		return na.family != "" && na.family == nb.family
	}
	return false
}

// temporalMetrics is the day-one temporal policy (EDR 4.3, D22): an applicable published fix is
// accepted as RL:O; a KEV listing proposes E:F but is not accepted, so E stays X.
func temporalMetrics(comp ScoreComponent, kev bool) []TemporalMetric {
	e := TemporalMetric{Metric: "E", State: MetricNotDefined, Used: "X"}
	if kev {
		e = TemporalMetric{Metric: "E", Evidence: "kev_listing", Proposed: "F", State: MetricProposed, Used: "X"}
	}
	rl := TemporalMetric{Metric: "RL", State: MetricNotDefined, Used: "X"}
	if comp.FixApplicable && comp.VerdictState != "cleared_vendor_fix" {
		rl = TemporalMetric{Metric: "RL", Evidence: "fix_published_applicable", Proposed: "O", State: MetricAcceptedByPolicy, Used: "O"}
	}
	rc := TemporalMetric{Metric: "RC", State: MetricNotDefined, Used: "X"}
	return []TemporalMetric{e, rl, rc}
}

// assessmentSuffix is the assessment's own temporal and environmental metrics, X omitted.
func assessmentSuffix(temporal []TemporalMetric, req ScoreRequirements) string {
	var b strings.Builder
	for _, m := range temporal {
		if m.Used != "X" {
			b.WriteString("/" + m.Metric + ":" + m.Used)
		}
	}
	for _, r := range []struct {
		key string
		v   RequirementValue
	}{{"CR", req.CR}, {"IR", req.IR}, {"AR", req.AR}} {
		switch r.v.Value {
		case "H", "M", "L":
			b.WriteString("/" + r.key + ":" + r.v.Value)
		}
	}
	return b.String()
}

var baseMetricKeys = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// baseVector keeps only the Base metrics of a canonical vector: temporal values never come from
// a source vector; they live on the assessment (EDR 4.3).
func baseVector(canonical string) string {
	v, _ := value.ParseCVSS3(canonical) // canonical is a vector the parser already accepted
	parts := []string{"CVSS:" + string(v.Version())}
	for _, k := range baseMetricKeys {
		parts = append(parts, k+":"+v.Metric(k))
	}
	return strings.Join(parts, "/")
}

// mustScores scores a vector built from an accepted Base vector and policy values.
func mustScores(vector string) Scores {
	v, _ := value.ParseCVSS3(vector)
	s := v.Scores()
	return Scores{Base: s.Base, Temporal: s.Temporal, Environmental: s.Environmental}
}
