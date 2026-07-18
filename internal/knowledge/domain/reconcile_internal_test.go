package domain

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

func cvssVal(t *testing.T, score float64) value.CVSS {
	t.Helper()
	c, err := value.NewCVSS(score, "")
	if err != nil {
		t.Fatalf("cvss: %v", err)
	}
	return c
}

func TestSeverityRank(t *testing.T) {
	ordered := []value.Severity{
		value.SeverityNone, value.SeverityLow, value.SeverityMedium, value.SeverityHigh, value.SeverityCritical,
	}
	for i := 1; i < len(ordered); i++ {
		if severityRank(ordered[i]) <= severityRank(ordered[i-1]) {
			t.Errorf("severityRank not strictly increasing at %s", ordered[i])
		}
	}
	if severityRank(value.SeverityUnknown) != 0 {
		t.Error("unknown severity should rank 0")
	}
	if severityRank(value.Severity("bogus")) != 0 {
		t.Error("unrecognized severity should rank 0")
	}
}

func TestHeadlineCandidate_beats(t *testing.T) {
	at := time.Unix(1_000, 0)
	base := headlineCandidate{set: true, rank: 1, observedAt: at, severity: value.SeverityHigh, cvss: cvssVal(t, 7.0), source: "m"}

	// Any set candidate beats an unset one.
	if !base.beats(headlineCandidate{}) {
		t.Error("a candidate should beat the unset zero value")
	}
	// Lower rank wins.
	lower := base
	lower.rank = 0
	if !lower.beats(base) || base.beats(lower) {
		t.Error("lower rank should win")
	}
	// Same rank, newer observation wins.
	newer := base
	newer.observedAt = at.Add(time.Hour)
	if !newer.beats(base) || base.beats(newer) {
		t.Error("newer observation should win")
	}
	// Same rank + time, higher severity wins.
	higher := base
	higher.severity = value.SeverityCritical
	if !higher.beats(base) || base.beats(higher) {
		t.Error("higher severity should win")
	}
	// Same rank/time/severity, higher CVSS wins.
	hiCVSS := base
	hiCVSS.cvss = cvssVal(t, 9.0)
	if !hiCVSS.beats(base) || base.beats(hiCVSS) {
		t.Error("higher CVSS should win")
	}
	// All else equal, lower source name wins.
	loSource := base
	loSource.source = "a"
	if !loSource.beats(base) || base.beats(loSource) {
		t.Error("lexically lower source should win")
	}
	// Fully equal → neither beats the other.
	if base.beats(base) {
		t.Error("an identical candidate should not beat itself")
	}
}

func TestEqualStrings(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a"}, []string{"a", "b"}, false},   // length mismatch
		{[]string{"a", "b"}, []string{"a", "c"}, false}, // element mismatch
	}
	for i, c := range cases {
		if got := equalStrings(c.a, c.b); got != c.want {
			t.Errorf("case %d: equalStrings = %v, want %v", i, got, c.want)
		}
	}
}

func TestEqualApplicabilities(t *testing.T) {
	x := Applicability{Package: "openssl", Status: "affected"}
	y := Applicability{Package: "zlib", Status: "affected"}
	cases := []struct {
		a, b []Applicability
		want bool
	}{
		{nil, nil, true},
		{[]Applicability{x}, []Applicability{x}, true},
		{[]Applicability{x}, []Applicability{x, y}, false}, // length mismatch
		{[]Applicability{x}, []Applicability{y}, false},    // element mismatch
	}
	for i, c := range cases {
		if got := equalApplicabilities(c.a, c.b); got != c.want {
			t.Errorf("case %d: equalApplicabilities = %v, want %v", i, got, c.want)
		}
	}
}

func TestEnterpriseView_equal(t *testing.T) {
	base := EnterpriseView{Severity: value.SeverityHigh, AffectedRanges: []string{"<3.0"}}
	same := EnterpriseView{Severity: value.SeverityHigh, AffectedRanges: []string{"<3.0"}}
	if !base.equal(same) {
		t.Error("identical views should be equal")
	}
	// Scalar difference.
	if base.equal(EnterpriseView{Severity: value.SeverityLow, AffectedRanges: []string{"<3.0"}}) {
		t.Error("differing severity should be unequal")
	}
	// Slice difference with equal scalars (reaches the slice comparison).
	if base.equal(EnterpriseView{Severity: value.SeverityHigh, AffectedRanges: []string{"<9.9"}}) {
		t.Error("differing ranges should be unequal")
	}
}
