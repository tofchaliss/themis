package domain

import (
	"reflect"
	"strings"
	"testing"
)

// groundedCtx mirrors the shape a real invocation carries: a Finding, its Faultline, and one
// matched component — the exact set Grounds() accepts.
func groundedCtx() AssembledContext {
	return AssembledContext{Projection: FindingAssessment{
		Finding: FindingView{
			ID:          "3c4c08b3-7339-4593-acf4-f2e9eee2618d",
			ReleaseID:   "007de00e-f3c8-48b0-a515-95e51fe9251c",
			FaultlineID: "a38d9c32-b93e-4797-accb-2fc003fae294",
			CVE:         "CVE-2026-41842",
			Components:  []string{"pkg:maven/org.springframework/spring-webmvc@6.2.11"},
		},
		Knowledge: FaultlineView{ID: "a38d9c32-b93e-4797-accb-2fc003fae294", CVE: "CVE-2026-41842"},
	}}
}

// The case observed on a live 20B model (2026-08-06), reproduced verbatim: two evidence refs
// correctly cited the faultline and passed every validation stage, while the narrative named a
// release the model was never given. Only the invented id is reported — the correctly-cited
// faultline and CVE in the same sentence are grounded and stay silent.
func TestUngroundedMentions_CatchesTheHallucinatedReleaseID(t *testing.T) {
	reasoning := "The CVE-2026-41842 vulnerability affects Spring Web MVC 6.2.11, which is " +
		"included in the release ee006ff7-f278-496e-8b31-ff0aba181db3. Faultline " +
		"a38d9c32-b93e-4797-accb-2fc003fae294 records the affected range."

	got := UngroundedMentions(reasoning, groundedCtx())
	want := []string{"ee006ff7-f278-496e-8b31-ff0aba181db3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UngroundedMentions = %v, want %v — only the id nobody supplied", got, want)
	}
}

// A rationale that names only what it was given produces nothing. This is the common case and
// must stay silent, or the warning becomes noise a reviewer learns to ignore.
func TestUngroundedMentions_SilentWhenEverythingIsGrounded(t *testing.T) {
	reasoning := "CVE-2026-41842 affects pkg:maven/org.springframework/spring-webmvc@6.2.11 " +
		"in release 007de00e-f3c8-48b0-a515-95e51fe9251c; see faultline " +
		"a38d9c32-b93e-4797-accb-2fc003fae294."
	if got := UngroundedMentions(reasoning, groundedCtx()); len(got) != 0 {
		t.Fatalf("UngroundedMentions = %v, want none — every id was supplied", got)
	}
}

// Ordinary prose has no identifiers. The check flags FALSE PRECISION, not bad writing: version
// numbers, package names and English words must never trip it, or every proposal carries a
// warning and the signal dies.
func TestUngroundedMentions_IgnoresProseVersionsAndNames(t *testing.T) {
	for _, s := range []string{
		"The component is vulnerable because version 6.2.11 predates the fix in 6.2.19.",
		"spring-webmvc is affected; upgrade to 7.0.8 or later.",
		"",
		"   ",
	} {
		if got := UngroundedMentions(s, groundedCtx()); len(got) != 0 {
			t.Errorf("UngroundedMentions(%q) = %v, want none", s, got)
		}
	}
}

func TestUngroundedMentions_CatchesEachIdentifierShape(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"uuid", "see 11111111-2222-3333-4444-555555555555 for details", "11111111-2222-3333-4444-555555555555"},
		{"cve", "this is related to CVE-2021-44228 as well", "CVE-2021-44228"},
		{"purl", "the culprit is pkg:npm/left-pad@1.3.0 here", "pkg:npm/left-pad@1.3.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UngroundedMentions(tc.text, groundedCtx())
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("UngroundedMentions = %v, want [%s]", got, tc.want)
			}
		})
	}
}

// Trailing sentence punctuation must not turn a grounded id into a false positive — the
// regexes are greedy enough to swallow it, and a spurious warning on a correct rationale is
// worse than no warning at all.
func TestUngroundedMentions_StripsTrailingPunctuation(t *testing.T) {
	text := "The affected package is pkg:maven/org.springframework/spring-webmvc@6.2.11."
	if got := UngroundedMentions(text, groundedCtx()); len(got) != 0 {
		t.Fatalf("UngroundedMentions = %v, want none — the trailing period is not part of the PURL", got)
	}
}

// Deterministic and bounded: the same rationale must produce byte-identical telemetry every
// run, and a model that has gone entirely off the rails must not emit an unbounded list.
func TestUngroundedMentions_SortedDedupedAndCapped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("CVE-2020-100")
		b.WriteByte(byte('0' + i%10))
		b.WriteString(" and CVE-2020-1000 again. ")
	}
	got := UngroundedMentions(b.String(), groundedCtx())
	if len(got) != maxRationaleWarnings {
		t.Fatalf("len = %d, want the %d cap", len(got), maxRationaleWarnings)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("not sorted/deduped: %v", got)
		}
	}
}
