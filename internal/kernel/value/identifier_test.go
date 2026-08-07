package value_test

import (
	"reflect"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func TestIdentifierTokens(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     []string
	}{
		// The live case: a model labelled the id it was asked to cite.
		{"labelled uuid", "faultline b1be6f86-2ecd-451f-9411-95f1f32fd501",
			[]string{"b1be6f86-2ecd-451f-9411-95f1f32fd501"}},
		{"bare uuid", "b1be6f86-2ecd-451f-9411-95f1f32fd501",
			[]string{"b1be6f86-2ecd-451f-9411-95f1f32fd501"}},
		{"cve in a sentence", "this concerns CVE-2021-44228 specifically", []string{"CVE-2021-44228"}},
		{"purl with trailing punctuation", "the package is pkg:npm/left-pad@1.3.0.", []string{"pkg:npm/left-pad@1.3.0"}},
		{"several, deduplicated, in order",
			"CVE-2021-44228 and CVE-2021-45046 and CVE-2021-44228 again",
			[]string{"CVE-2021-44228", "CVE-2021-45046"}},
		// Prose carries no identifiers. This is what keeps the check about false PRECISION
		// rather than about writing style.
		{"prose", "the installed version 6.2.11 predates the fix in 6.2.19", nil},
		{"empty", "", nil},
		{"blank", "   ", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := value.IdentifierTokens(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("IdentifierTokens(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// The two cases that make extraction safe where substring matching would not be. A caller
// checks each EXTRACTED TOKEN against its grounding set, so what matters is that the tokens are
// whole and anchored.
func TestIdentifierTokens_AreWholeAndAnchored(t *testing.T) {
	// A longer CVE must yield ITSELF, never the shorter id it contains as a prefix — the
	// difference between anchored token extraction and substring matching, and the reason the
	// caller can safely require exact set membership on what comes back.
	got := value.IdentifierTokens("CVE-2024-10000")
	if len(got) != 1 || got[0] != "CVE-2024-10000" {
		t.Fatalf("got %v, want exactly [CVE-2024-10000] — a prefix match would ground the wrong CVE", got)
	}
	// A negated claim still yields its identifier: extraction is not comprehension. That is
	// acceptable because `ref` is an identifier field, not a sentence, and the recommendation's
	// stance lives in a separate field this cannot invert.
	if got := value.IdentifierTokens("not CVE-2024-1000"); len(got) != 1 || got[0] != "CVE-2024-1000" {
		t.Fatalf("got %v, want [CVE-2024-1000]", got)
	}
}

// Trailing sentence punctuation is stripped: a PURL at the end of a clause would otherwise
// carry the punctuation into the caller's exact set-membership check and look unsupplied.
func TestIdentifierTokens_StripsTrailingPunctuation(t *testing.T) {
	// A PURL match ending entirely in trimmable punctuation.
	if got := value.IdentifierTokens("pkg:npm/a@1.0.0)]}"); len(got) != 1 || got[0] != "pkg:npm/a@1.0.0" {
		t.Fatalf("got %v, want the PURL with trailing punctuation removed", got)
	}
}

// The same identifier reached through two different patterns is reported once, so a caller's
// per-token check is not run redundantly and telemetry stays stable.
func TestIdentifierTokens_DeduplicatesAcrossPatterns(t *testing.T) {
	in := "CVE-2021-44228 CVE-2021-44228 b1be6f86-2ecd-451f-9411-95f1f32fd501 b1be6f86-2ecd-451f-9411-95f1f32fd501"
	got := value.IdentifierTokens(in)
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 unique tokens", got)
	}
}
