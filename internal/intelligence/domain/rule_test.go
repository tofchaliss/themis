package domain

import (
	"reflect"
	"testing"
)

func mkAC(components, ranges []string, cve string) AssembledContext {
	return AssembledContext{
		Finding:   FindingView{Components: components, CVE: cve},
		Faultline: FaultlineView{AffectedRanges: ranges, CVE: cve},
	}
}

func TestVersionRangeRuleID(t *testing.T) {
	if got := (VersionRangeRule{}).ID(); got != "version-range" {
		t.Fatalf("ID() = %q, want version-range", got)
	}
}

func TestVersionRangeRuleDefers(t *testing.T) {
	cases := []struct {
		name string
		ac   AssembledContext
	}{
		{"no reconciled range", mkAC([]string{"pkg:pypi/foo@2.0"}, nil, "CVE-1")},
		{"no matched components", mkAC(nil, []string{">= 1.0, < 3.0"}, "CVE-1")},
		{"unparseable component (no pkg: scheme)", mkAC([]string{"npm:foo@1.0"}, []string{">= 1.0, < 3.0"}, "CVE-1")},
		{"purl without a type slash", mkAC([]string{"pkg:foo@1.0"}, []string{">= 1.0, < 3.0"}, "CVE-1")},
		{"component carries no version", mkAC([]string{"pkg:apk/openssl"}, []string{">= 1.0, < 3.0"}, "CVE-1")},
		{"component in range", mkAC([]string{"pkg:pypi/foo@2.0"}, []string{">= 1.0, < 3.0"}, "CVE-1")},
		{"undecidable range (none)", mkAC([]string{"pkg:pypi/foo@2.0"}, []string{"none"}, "CVE-1")},
		{"one out, one in → defer", mkAC([]string{"pkg:pypi/foo@5.0", "pkg:pypi/bar@2.0"}, []string{">= 1.0, < 3.0"}, "CVE-1")},
	}
	for _, c := range cases {
		if d, ok := (VersionRangeRule{}).Decide(c.ac); ok {
			t.Errorf("%s: expected defer, got decision %+v", c.name, d)
		}
	}
}

func TestVersionRangeRuleDecidesNotAffected(t *testing.T) {
	ac := mkAC([]string{"pkg:pypi/foo@5.0"}, []string{">= 1.0, < 3.0"}, "CVE-2024-9999")
	d, ok := (VersionRangeRule{}).Decide(ac)
	if !ok {
		t.Fatal("expected a decision for a provably out-of-range component")
	}
	if d.Stance != StanceNotAffected {
		t.Errorf("stance = %q, want not_affected", d.Stance)
	}
	if d.RuleID != "version-range" || d.Reason == "" {
		t.Errorf("provenance = %q/%q, want version-range + a reason", d.RuleID, d.Reason)
	}
	want := []Evidence{{Kind: "component", Ref: "pkg:pypi/foo@5.0"}, {Kind: "cve", Ref: "CVE-2024-9999"}}
	if !reflect.DeepEqual(d.Evidence, want) {
		t.Errorf("evidence = %v, want %v (components + CVE, all grounded)", d.Evidence, want)
	}
	// Every cited evidence ref must exist in the grounding (anti-hallucination parity).
	for _, e := range d.Evidence {
		if !ac.Grounds(e.Ref) {
			t.Errorf("evidence %q is not grounded in the assembled context", e.Ref)
		}
	}
}

func TestVersionRangeRuleDecidesWithoutCVE(t *testing.T) {
	// No CVE on the Faultline → evidence is just the component purls (CVE branch not taken).
	ac := mkAC([]string{"pkg:apk/openssl@1.1.1k-r0?arch=x86_64"}, []string{"< 1.0"}, "")
	d, ok := (VersionRangeRule{}).Decide(ac)
	if !ok {
		t.Fatal("expected a decision (apk 1.1.1k-r0 is outside < 1.0, qualifiers stripped)")
	}
	want := []Evidence{{Kind: "component", Ref: "pkg:apk/openssl@1.1.1k-r0?arch=x86_64"}}
	if !reflect.DeepEqual(d.Evidence, want) {
		t.Errorf("evidence = %v, want %v (no CVE appended)", d.Evidence, want)
	}
}

func TestRuleDecisionAsOutput(t *testing.T) {
	d := RuleDecision{
		Stance:   StanceNotAffected,
		RuleID:   "version-range",
		Reason:   "out of range",
		Evidence: []Evidence{{Kind: "component", Ref: "pkg:pypi/foo@5.0"}},
	}
	out := d.AsOutput("F1")
	if out.FindingID != "F1" || out.RecommendedStance != "not_affected" || out.Confidence != 1.0 {
		t.Errorf("output = %+v, want F1/not_affected/1.0", out)
	}
	if out.Reasoning != "out of range" {
		t.Errorf("reasoning = %q", out.Reasoning)
	}
	if want := []RawEvidence{{Kind: "component", Ref: "pkg:pypi/foo@5.0"}}; !reflect.DeepEqual(out.Evidence, want) {
		t.Errorf("evidence = %v, want %v", out.Evidence, want)
	}
}

func TestRuleSetFirstDecisionWins(t *testing.T) {
	decision := RuleDecision{Stance: StanceNotAffected, RuleID: "fake"}
	rs := RuleSet{
		fakeRule{id: "defers"},                           // defers → loop continues
		fakeRule{id: "decides", dec: decision, ok: true}, // first to decide wins
		fakeRule{id: "never-reached", dec: RuleDecision{Stance: StanceAffected}, ok: true},
	}
	got, ok := rs.Decide(AssembledContext{})
	if !ok || got.RuleID != "fake" {
		t.Fatalf("RuleSet.Decide = %+v (ok=%v), want the first deciding rule", got, ok)
	}
}

func TestRuleSetDefersWhenNoneDecide(t *testing.T) {
	if _, ok := (RuleSet{fakeRule{id: "a"}, fakeRule{id: "b"}}).Decide(AssembledContext{}); ok {
		t.Fatal("expected defer when no rule decides")
	}
	if _, ok := (RuleSet{}).Decide(AssembledContext{}); ok {
		t.Fatal("expected defer for an empty rule set")
	}
}

// fakeRule is a test double for RuleSet ordering.
type fakeRule struct {
	id  string
	dec RuleDecision
	ok  bool
}

func (f fakeRule) ID() string                                   { return f.id }
func (f fakeRule) Decide(AssembledContext) (RuleDecision, bool) { return f.dec, f.ok }
