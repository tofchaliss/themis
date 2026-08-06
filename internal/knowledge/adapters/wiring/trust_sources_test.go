package wiring

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

// shippedSources is every source id Knowledge can currently record a Proposal under.
//
// This list is the **manual half** of the classification guard: it must be extended when
// a feed or ACL is added. Deriving it from a single shipped-source registry — so adding a
// feed cannot skip classification at all — is filed in `docs/BACKLOG.md`. Until then this
// test at least fails loudly rather than letting an unclassified source fail closed
// silently in production.
var shippedSources = []string{
	"osv", "nvd", "epss", "kev", "epsskev", "exploitdb",
	"redhat", "vexfeed", "vex",
	"scanner", "scanner-report",
}

// Every shipped source must be classified. An unregistered source still fails closed to
// Asserted at runtime, but that is a safety net, not a substitute for deciding — a feed
// republishing a public record would be silently under-trusted and its conclusions kept
// out of policy auto-acceptance for no reason.
func TestEveryKnownSourceIsClassified(t *testing.T) {
	for _, s := range shippedSources {
		if _, ok := trustBySource[s]; !ok {
			t.Errorf("source %q is shipped but not classified in trustBySource — decide whether its "+
				"output is reproducible (Observed), declared (Asserted), or reasoned (Inferred)", s)
		}
	}
}

// A malformed table entry would fail closed at runtime and hide the real problem here.
func TestTrustTableEntriesAreValid(t *testing.T) {
	for s, c := range trustBySource {
		if !c.Valid() {
			t.Errorf("source %q has invalid trust class %q", s, c)
		}
	}
}

// The calibration cases from EDR-TRUST-01 T2, asserted against the table we actually ship
// rather than against a fixture — this is where a wrong call does real damage.
func TestShippedTrustClassifications(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   value.TrustClass
		why    string
	}{
		{"osv", value.TrustObserved, "a public record — re-fetching reproduces it"},
		{"nvd", value.TrustObserved, "a public record"},
		{"kev", value.TrustObserved, "a public catalog"},
		{"redhat", value.TrustAsserted, "a judgment about the vendor's own build; nothing can re-run it"},
		{"vexfeed", value.TrustAsserted, "vendor VEX statements are declarations"},
		{"scanner", value.TrustAsserted, "a scanner verdict rests on its own matching heuristics"},
	} {
		if got := newTrustPolicy().ClassOf(tc.source); got != tc.want {
			t.Errorf("ClassOf(%q) = %q, want %q — %s", tc.source, got, tc.want, tc.why)
		}
	}
}

// Nothing Knowledge ingests today is Inferred: AI-sourced Knowledge Proposals
// (EDR-INTELLIGENCE-01 D2) are not wired, since Intelligence currently proposes only into
// Governance. When that path lands, its source MUST be added here as Inferred — the
// fail-closed default is Asserted, which would under-classify it and is the one case
// where failing closed is not conservative enough. Tracked in `docs/BACKLOG.md`.
func TestNoShippedSourceIsInferredYet(t *testing.T) {
	for s, c := range trustBySource {
		if c == value.TrustInferred {
			t.Errorf("source %q is classified Inferred; if the AI→Knowledge proposal path has landed, "+
				"remove this test and confirm the constitutional bar (T4) covers it", s)
		}
	}
}
