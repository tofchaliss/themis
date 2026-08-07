package value

import (
	"fmt"
	"math"
	"strings"
)

// CVSS is a Common Vulnerability Scoring System verdict: a base score in [0.0, 10.0]
// and its (optional) vector string. It records what a source reported and derives the
// qualitative Severity band. It records the source's score as given — reconciliation of competing
// scores is a Knowledge concern, not a kernel one — but `BaseScoreFromVector` below can DERIVE a
// v3.x score when a source publishes a vector and no number, which is not the same thing: deriving
// from a fully-specified formula is reproducible evidence, where preferring one source's number
// over another's is a policy.
type CVSS struct {
	score  float64
	vector string
}

// NewCVSS validates and constructs a CVSS value. The base score must lie within
// [0.0, 10.0]; the vector is optional and stored trimmed.
func NewCVSS(score float64, vector string) (CVSS, error) {
	if score < 0 || score > 10 {
		return CVSS{}, fmt.Errorf("cvss: score %.1f out of range [0.0, 10.0]", score)
	}
	return CVSS{score: score, vector: strings.TrimSpace(vector)}, nil
}

// Score returns the CVSS base score.
func (c CVSS) Score() float64 { return c.score }

// Vector returns the CVSS vector string (may be empty).
func (c CVSS) Vector() string { return c.vector }

// Severity returns the qualitative band derived from the base score.
func (c CVSS) Severity() Severity { return SeverityFromCVSSScore(c.score) }

// IsZero reports whether the value carries neither a score nor a vector.
func (c CVSS) IsZero() bool { return c.score == 0 && c.vector == "" }

// --- vector selection + base-score derivation --------------------------------------------

// CVSSVectorVersion reports the CVSS version a vector string declares: "4.0", "3.1", "3.0", "2",
// or "" when it is not a recognisable vector.
func CVSSVectorVersion(vector string) string {
	v := strings.TrimSpace(vector)
	switch {
	case strings.HasPrefix(v, "CVSS:4.0/"):
		return "4.0"
	case strings.HasPrefix(v, "CVSS:3.1/"):
		return "3.1"
	case strings.HasPrefix(v, "CVSS:3.0/"):
		return "3.0"
	case looksLikeCVSSv2(v):
		return "2"
	default:
		return ""
	}
}

// looksLikeCVSSv2 reports whether a prefix-less string is actually a v2 vector.
//
// A v2 vector carries no version prefix (e.g. "AV:N/AC:L/Au:N/C:P/I:P/A:P"), so "no CVSS: prefix"
// was originally taken to mean v2 — which made ANY non-empty string a vector, and an arbitrary
// string then outranked nothing and got selected. That is the same shape as RANGE-PARSE-1: a
// recogniser loose enough to accept garbage turns unparseable input into a value the system acts
// on. `Au` is the discriminator — v2's Authentication metric, replaced by PR in v3.
func looksLikeCVSSv2(v string) bool {
	return strings.Contains(v, "AV:") && strings.Contains(v, "Au:")
}

// cvssVectorRank orders vectors by how much this system can DO with them, best first.
//
// v3.1 and v3.0 rank above v4.0 deliberately: their base score is derived from the vector here, so
// a v3 vector alone yields a usable number, while a v4 vector without an accompanying score does
// not. This is a capability ordering, not a claim that v3 is a better standard — when v4 scoring
// lands, the order should be revisited.
func cvssVectorRank(version string) int {
	switch version {
	case "3.1":
		return 4
	case "3.0":
		return 3
	case "4.0":
		return 2
	case "2":
		return 1
	default:
		return 0
	}
}

// PreferredCVSSVector picks the most usable vector from a set (KN CVSS-v4.0 gap).
//
// Feeds publish several: OSV lists CVSS_V2, CVSS_V3 and CVSS_V4 entries side by side, and taking
// the FIRST one — which the OSV ACL did — means whichever the feed happened to order first decides
// the enterprise's severity. A v2 vector winning over a v3.1 one is a silent downgrade of the
// evidence.
func PreferredCVSSVector(vectors []string) string {
	best, bestRank := "", 0
	for _, v := range vectors {
		if r := cvssVectorRank(CVSSVectorVersion(v)); r > bestRank {
			best, bestRank = strings.TrimSpace(v), r
		}
	}
	return best
}

// BaseScoreFromVector computes the CVSS **v3.x** base score from a vector string, per the CVSS 3.1
// specification. It returns 0 for anything it cannot compute — a v2 or v4.0 vector, a malformed
// one, or a vector missing a required metric.
//
// It exists because a numeric score is not always published beside the vector: OSV carries the
// vector in `severity[]` and the number only in a database-specific extension, so a CVE with a
// vector and no extension landed `severity=unknown` / `score=0` — and an unknown severity scores 0,
// which sorts a real vulnerability to the bottom of a triage queue.
//
// Deriving rather than guessing: the formula is fully specified and deterministic, so the number is
// reproducible from evidence the enterprise holds — Observed, in trust terms, not Asserted.
func BaseScoreFromVector(vector string) float64 {
	if CVSSVectorVersion(vector) != "3.1" && CVSSVectorVersion(vector) != "3.0" {
		return 0 // v2 and v4.0 use different formulas; not computed here
	}
	m := map[string]string{}
	for _, part := range strings.Split(strings.TrimSpace(vector), "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	scopeChanged := m["S"] == "C"
	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ui, ok2 := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	c, ok3 := cvssImpactMetric(m["C"])
	i, ok4 := cvssImpactMetric(m["I"])
	a, ok5 := cvssImpactMetric(m["A"])
	ac, ok6 := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	pr, ok7 := cvssPrivilegesRequired(m["PR"], scopeChanged)
	scopeKnown := m["S"] == "U" || m["S"] == "C"
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || !scopeKnown {
		return 0 // a missing or unrecognised metric — defer rather than emit a wrong number
	}

	iscBase := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui
	score := impact + exploitability
	if scopeChanged {
		score = 1.08 * score
	}
	if score > 10 {
		score = 10
	}
	// CVSS rounds UP to one decimal (roundup(), §Appendix A) — not to nearest, which would
	// under-report a score sitting just above a band boundary.
	return math.Ceil(score*10) / 10
}

func cvssImpactMetric(v string) (float64, bool) {
	f, ok := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[v]
	return f, ok
}

// cvssPrivilegesRequired weights PR by scope: a changed scope makes "low" and "high" privileges
// matter less, because the attacker crosses a security boundary regardless.
func cvssPrivilegesRequired(v string, scopeChanged bool) (float64, bool) {
	switch v {
	case "N":
		return 0.85, true
	case "L":
		if scopeChanged {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if scopeChanged {
			return 0.5, true
		}
		return 0.27, true
	default:
		return 0, false
	}
}
