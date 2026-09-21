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
		{[]string{"a"}, []string{"a", "b"}, false},      // length mismatch
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

// EDR-VEX-02 D7: two statements for ONE package now differ only by the product they cover, so
// the sort must be total over the scope as well. Without the scope tiebreak the order would
// depend on map iteration — and the view is compared for equality, so a nondeterministic order
// would report ViewChanged on every fold and re-announce work that never happened.
func TestSortedApplicabilitiesIsTotalOverScope(t *testing.T) {
	rhel7 := Applicability{Package: "httpd", Status: "not_affected", Justification: "same",
		Scope: value.ProductScope{Family: value.FamilyEnterpriseLinux, Major: "7"}}
	rhel8 := Applicability{Package: "httpd", Status: "not_affected", Justification: "same",
		Scope: value.ProductScope{Family: value.FamilyEnterpriseLinux, Major: "8"}}
	pipelines := Applicability{Package: "httpd", Status: "not_affected", Justification: "same",
		Scope: value.ProductScope{Family: "openshift_pipelines", Major: "1"}}

	set := map[Applicability]struct{}{rhel8: {}, pipelines: {}, rhel7: {}}
	first := sortedApplicabilities(set)
	if len(first) != 3 {
		t.Fatalf("got %d statements, want 3 — differing scopes must not collapse", len(first))
	}
	// Family orders before major, and both are compared: enterprise-linux/7 < 8 < openshift…
	if first[0].Scope.Major != "7" || first[1].Scope.Major != "8" || first[2].Scope.Family != "openshift_pipelines" {
		t.Errorf("order = %+v, want enterprise-linux/7, enterprise-linux/8, openshift_pipelines/1", first)
	}
	// Repeated over a freshly-built map: a stable order cannot depend on iteration order.
	for i := 0; i < 20; i++ {
		again := sortedApplicabilities(map[Applicability]struct{}{pipelines: {}, rhel7: {}, rhel8: {}})
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("run %d position %d = %+v, want %+v — the sort is not total", i, j, again[j], first[j])
			}
		}
	}
}
