package value

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// CVSS 3.0 / 3.1 full calculator (EDR-SCORING-01 S1, R-C1..R-C6).
//
// It parses every Base, Temporal and Environmental metric of a v3 vector, keeps "not defined" (X)
// apart from a value, and computes the three scores with the specification's equations and its
// Roundup. It is pure and deterministic: no I/O, no policy. Which vector to score, and which
// temporal or environmental values to put in it, are Governance decisions (EDR-SCORING-01 4.1-4.4);
// this file only does the arithmetic.

// CVSS3Version is the CVSS specification version a parsed vector declares.
type CVSS3Version string

// The two supported v3 versions. 3.0 and 3.1 differ in Roundup and in the modified-impact equation
// for a changed scope.
const (
	CVSS30 CVSS3Version = "3.0"
	CVSS31 CVSS3Version = "3.1"
)

// ErrCVSS3Vector is the sentinel every parse refusal wraps, so a caller can tell "refused with a
// reason" from any other error. A refused vector is never scored 0 (R-C3).
var ErrCVSS3Vector = errors.New("cvss3: invalid vector")

// cvss3Metric describes one metric: the values it allows and whether a vector must carry it.
type cvss3Metric struct {
	key      string
	values   []string
	required bool
}

// cvss3Metrics is the metric order of the specification (Base, Temporal, Environmental). The order
// is also the canonical output order.
var cvss3Metrics = []cvss3Metric{
	{"AV", []string{"N", "A", "L", "P"}, true},
	{"AC", []string{"L", "H"}, true},
	{"PR", []string{"N", "L", "H"}, true},
	{"UI", []string{"N", "R"}, true},
	{"S", []string{"U", "C"}, true},
	{"C", []string{"H", "L", "N"}, true},
	{"I", []string{"H", "L", "N"}, true},
	{"A", []string{"H", "L", "N"}, true},
	{"E", []string{"X", "H", "F", "P", "U"}, false},
	{"RL", []string{"X", "U", "W", "T", "O"}, false},
	{"RC", []string{"X", "C", "R", "U"}, false},
	{"CR", []string{"X", "H", "M", "L"}, false},
	{"IR", []string{"X", "H", "M", "L"}, false},
	{"AR", []string{"X", "H", "M", "L"}, false},
	{"MAV", []string{"X", "N", "A", "L", "P"}, false},
	{"MAC", []string{"X", "L", "H"}, false},
	{"MPR", []string{"X", "N", "L", "H"}, false},
	{"MUI", []string{"X", "N", "R"}, false},
	{"MS", []string{"X", "U", "C"}, false},
	{"MC", []string{"X", "H", "L", "N"}, false},
	{"MI", []string{"X", "H", "L", "N"}, false},
	{"MA", []string{"X", "H", "L", "N"}, false},
}

// CVSS3Vector is a parsed CVSS 3.0 / 3.1 vector. Every optional metric not present in the source
// string reads as "X" (not defined), which is kept distinct from any value.
type CVSS3Vector struct {
	version CVSS3Version
	metrics map[string]string
}

// CVSS3Scores are the three scores of one vector. Temporal equals Base and Environmental follows
// the equations when the optional metrics are X; nothing is ever defaulted to a guess.
type CVSS3Scores struct {
	Base          float64
	Temporal      float64
	Environmental float64
}

// ParseCVSS3 parses a CVSS 3.0 or 3.1 vector string. It refuses, with a reason wrapping
// ErrCVSS3Vector, a missing or unknown version prefix, an unknown metric, a value the metric does
// not allow, a metric given twice, and a missing Base metric.
func ParseCVSS3(vector string) (CVSS3Vector, error) {
	s := strings.TrimSpace(vector)
	var version CVSS3Version
	switch {
	case strings.HasPrefix(s, "CVSS:3.1/"):
		version = CVSS31
	case strings.HasPrefix(s, "CVSS:3.0/"):
		version = CVSS30
	default:
		return CVSS3Vector{}, fmt.Errorf("%w: not a CVSS 3.0 or 3.1 vector", ErrCVSS3Vector)
	}
	allowed := make(map[string]cvss3Metric, len(cvss3Metrics))
	for _, m := range cvss3Metrics {
		allowed[m.key] = m
	}
	got := map[string]string{}
	for _, part := range strings.Split(s[len("CVSS:3.1/"):], "/") {
		key, val, ok := strings.Cut(part, ":")
		if !ok || key == "" || val == "" {
			return CVSS3Vector{}, fmt.Errorf("%w: malformed component %q", ErrCVSS3Vector, part)
		}
		def, known := allowed[key]
		if !known {
			return CVSS3Vector{}, fmt.Errorf("%w: unknown metric %q", ErrCVSS3Vector, key)
		}
		if _, dup := got[key]; dup {
			return CVSS3Vector{}, fmt.Errorf("%w: metric %q given twice", ErrCVSS3Vector, key)
		}
		if !containsString(def.values, val) {
			return CVSS3Vector{}, fmt.Errorf("%w: metric %s does not allow %q", ErrCVSS3Vector, key, val)
		}
		got[key] = val
	}
	for _, m := range cvss3Metrics {
		if _, ok := got[m.key]; ok {
			continue
		}
		if m.required {
			return CVSS3Vector{}, fmt.Errorf("%w: base metric %s missing", ErrCVSS3Vector, m.key)
		}
		got[m.key] = "X"
	}
	return CVSS3Vector{version: version, metrics: got}, nil
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Version returns the declared CVSS version.
func (v CVSS3Vector) Version() CVSS3Version { return v.version }

// Metric returns one metric's value; an optional metric the source did not set reads "X". An
// unknown key returns "".
func (v CVSS3Vector) Metric(key string) string { return v.metrics[key] }

// String returns the canonical vector: the version prefix, then every metric in specification
// order, omitting optional metrics that are X. Two vectors with the same meaning give the same
// string, whatever order or explicit X the source used.
func (v CVSS3Vector) String() string {
	var b strings.Builder
	b.WriteString("CVSS:")
	b.WriteString(string(v.version))
	for _, m := range cvss3Metrics {
		val := v.metrics[m.key]
		if !m.required && val == "X" {
			continue
		}
		b.WriteString("/")
		b.WriteString(m.key)
		b.WriteString(":")
		b.WriteString(val)
	}
	return b.String()
}

// Scores computes Base, Temporal and Environmental with the equations of the declared version.
func (v CVSS3Vector) Scores() CVSS3Scores {
	m := v.metrics
	round := v.roundup

	// Base.
	scopeChanged := m["S"] == "C"
	iss := 1 - (1-cvss3CIA[m["C"]])*(1-cvss3CIA[m["I"]])*(1-cvss3CIA[m["A"]])
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * cvss3AV[m["AV"]] * cvss3AC[m["AC"]] * cvss3PR(m["PR"], scopeChanged) * cvss3UI[m["UI"]]
	var base float64
	if impact > 0 {
		if scopeChanged {
			base = round(math.Min(1.08*(impact+exploitability), 10))
		} else {
			base = round(math.Min(impact+exploitability, 10))
		}
	}

	// Temporal.
	temporalFactor := cvss3E[m["E"]] * cvss3RL[m["RL"]] * cvss3RC[m["RC"]]
	temporal := round(base * temporalFactor)

	// Environmental: modified metrics fall back to the base metric when X.
	mod := func(key, baseKey string) string {
		if val := m[key]; val != "X" {
			return val
		}
		return m[baseKey]
	}
	mScopeChanged := mod("MS", "S") == "C"
	miss := math.Min(1-
		(1-cvss3Req[m["CR"]]*cvss3CIA[mod("MC", "C")])*
			(1-cvss3Req[m["IR"]]*cvss3CIA[mod("MI", "I")])*
			(1-cvss3Req[m["AR"]]*cvss3CIA[mod("MA", "A")]), 0.915)
	var mImpact float64
	switch {
	case !mScopeChanged:
		mImpact = 6.42 * miss
	case v.version == CVSS31:
		mImpact = 7.52*(miss-0.029) - 3.25*math.Pow(miss*0.9731-0.02, 13)
	default:
		mImpact = 7.52*(miss-0.029) - 3.25*math.Pow(miss-0.02, 15)
	}
	mExploitability := 8.22 * cvss3AV[mod("MAV", "AV")] * cvss3AC[mod("MAC", "AC")] *
		cvss3PR(mod("MPR", "PR"), mScopeChanged) * cvss3UI[mod("MUI", "UI")]
	var environmental float64
	if mImpact > 0 {
		if mScopeChanged {
			environmental = round(round(math.Min(1.08*(mImpact+mExploitability), 10)) * temporalFactor)
		} else {
			environmental = round(round(math.Min(mImpact+mExploitability, 10)) * temporalFactor)
		}
	}
	return CVSS3Scores{Base: base, Temporal: temporal, Environmental: environmental}
}

// roundup rounds to one decimal, always upwards.
//
// 3.1 defines Roundup on integers so that floating-point noise (5.0 x 0.92 = 4.6000000000000005)
// does not lift a score by 0.1. 3.0 specifies the same "smallest one-decimal number not below the
// input" without saying how; the naive float ceiling produces exactly that noise, so 3.0 uses the
// same exact rounding. Both versions agree with an exact decimal implementation (the oracle test).
func (v CVSS3Vector) roundup(x float64) float64 { return cvss31Roundup(x) }

// cvss31Roundup is CVSS 3.1 Appendix A Roundup.
func cvss31Roundup(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

var (
	cvss3AV  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvss3AC  = map[string]float64{"L": 0.77, "H": 0.44}
	cvss3UI  = map[string]float64{"N": 0.85, "R": 0.62}
	cvss3CIA = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	cvss3E   = map[string]float64{"X": 1, "H": 1, "F": 0.97, "P": 0.94, "U": 0.91}
	cvss3RL  = map[string]float64{"X": 1, "U": 1, "W": 0.97, "T": 0.96, "O": 0.95}
	cvss3RC  = map[string]float64{"X": 1, "C": 1, "R": 0.96, "U": 0.92}
	cvss3Req = map[string]float64{"X": 1, "H": 1.5, "M": 1, "L": 0.5}
)

// cvss3PR weights Privileges Required by the (modified) scope.
func cvss3PR(v string, scopeChanged bool) float64 {
	switch {
	case v == "N":
		return 0.85
	case v == "L" && scopeChanged:
		return 0.68
	case v == "L":
		return 0.62
	case scopeChanged: // H
		return 0.5
	default: // H, scope unchanged
		return 0.27
	}
}
