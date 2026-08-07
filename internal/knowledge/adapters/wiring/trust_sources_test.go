package wiring

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// Every shipped source must be classified. The list is DERIVED (see shippedSources in
// trust_sources.go) — registering a feed ACL is how a source becomes reachable at all, so a new
// feed cannot skip classification: this fails the build before it can fail closed in production.
//
// An unregistered source still degrades to Asserted at runtime, but that is a safety net, not a
// substitute for deciding. A feed republishing a public record would otherwise be silently
// under-trusted and its conclusions kept out of the one auto-accept rule that ships (D15).
func TestEveryKnownSourceIsClassified(t *testing.T) {
	for _, s := range shippedSources() {
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
		{"epsskev", value.TrustObserved, "the EPSS/KEV/ExploitDB sweep — public catalogs, reproducible on re-fetch"},
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

// The guard runs in BOTH directions. The forward check stops a shipped source going
// unclassified; this one stops the table describing sources that no longer exist.
//
// A stale entry is not harmless. It reads as a considered decision about a live source, so the
// next person to review "what is this feed worth?" answers a question about something that is
// not there, and a genuinely missing classification is easier to overlook in a table padded
// with fiction. Three such entries ("epss", "kev", "scanner-report") had accumulated and were
// removed when this check was added.
func TestTrustTableClassifiesOnlyShippedSources(t *testing.T) {
	shipped := map[string]bool{}
	for _, s := range shippedSources() {
		shipped[s] = true
	}
	for s := range trustBySource {
		if !shipped[s] {
			t.Errorf("trustBySource classifies %q, which nothing ships — remove it, or register the "+
				"source that produces it", s)
		}
	}
}

// The derived enumeration must actually reach the sources the ACL registry knows about. If
// this ever returns fewer than the registry does, the derivation has been broken and the
// forward guard silently stops guarding.
func TestShippedSourcesCoversTheFeedRegistry(t *testing.T) {
	got := map[string]bool{}
	for _, s := range shippedSources() {
		got[s] = true
	}
	for _, s := range feed.NewRegistry().Sources() {
		if !got[s] {
			t.Errorf("feed registry source %q is missing from shippedSources()", s)
		}
	}
	// The one non-ACL source: an operator-uploaded VEX document.
	if !got[app.VEXDocumentSource] {
		t.Errorf("the uploaded-VEX source %q is missing from shippedSources()", app.VEXDocumentSource)
	}
}

// applicabilitySources are the sources that can raise an APPLICABILITY proposal — a vendor VEX
// statement about a package. Kept beside the guard below because that guard is only sound while
// this list is complete; adding an applicability-producing source without adding it here is the
// one way to slip past.
var applicabilitySources = []string{"redhat", "vexfeed", "vex"}

// TRUST-1's deferral has an expiry, and this is it.
//
// `domain.Applicability` carries no per-statement trust class, and that is CORRECT today only
// because every applicability originates from vendor VEX or an uploaded VEX document — uniformly
// **Asserted**, so a per-statement class would carry no information. The moment a source with a
// DIFFERENT class can raise an applicability (a signed build manifest would be Observed; an AI
// capability would be Inferred), two statements on one card deserve different classes and the
// reconciled view can no longer represent that.
//
// Worse, it would fail SILENTLY: `Reconcile` uses `Applicability{Package, Status, Justification}`
// as its dedup key, so a derivable statement and an asserted one saying the same thing collapse
// into one — and the surviving entry's provenance is whichever the map happened to keep.
//
// This test fails the build at exactly that moment, so the deferral cannot quietly become a defect.
func TestApplicabilitySourcesAreUniformlyAsserted(t *testing.T) {
	policy := newTrustPolicy()
	for _, src := range applicabilitySources {
		if c := policy.ClassOf(src); c != value.TrustAsserted {
			t.Errorf("applicability source %q is now %q, not Asserted — TRUST-1 is no longer deferrable: "+
				"domain.Applicability needs a per-statement trust class, and Reconcile's dedup key must stop "+
				"collapsing statements of different provenance", src, c)
		}
	}
}

// The guard is only sound while applicabilitySources is complete. A source that produces
// applicability proposals but is missing from that list would slip past the check above, so this
// asserts every name in it is a real, classified source.
func TestApplicabilitySourcesAreAllShipped(t *testing.T) {
	shipped := map[string]bool{}
	for _, s := range shippedSources() {
		shipped[s] = true
	}
	for _, src := range applicabilitySources {
		if !shipped[src] {
			t.Errorf("applicability source %q is not a shipped source — the list has drifted from reality", src)
		}
	}
}
