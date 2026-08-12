package wiring

import (
	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// trustBySource is the single reviewable answer to "what is this source's output worth?"
// (EDR-TRUST-01 T2). It lives beside the precedence table in the composition root for the
// same reason: the domain owns the mechanism, the composition root owns the table.
//
// The classifying question is **derivable vs declared** — can this be re-derived, or must
// someone be believed? Note that *how* a fact arrives decides nothing: an OSV range and a
// Red Hat `not_affected` reach us by the identical HTTP fetch of a JSON document. What
// separates them is that the range is a public record anyone can check, while the
// `not_affected` is a judgment nothing can re-run.
//
// Adding a source **must** mean answering that question here. `TestEveryKnownSourceIsClassified`
// fails the build if a shipped source is missing, so an unclassified feed cannot reach
// production and quietly fail closed.
var trustBySource = map[string]value.TrustClass{
	// Public records, independently published and reproducible on re-fetch.
	"osv":       value.TrustObserved,
	"nvd":       value.TrustObserved,
	"epsskev":   value.TrustObserved, // the combined EPSS/KEV/ExploitDB sweep records under this one id
	"exploitdb": value.TrustObserved,
	// The Alpine secdb is a public per-branch record of fixed apk versions — re-fetching
	// reproduces it, and unlike the Red Hat feed it carries no judgment statements (no
	// not_affected, no severity), only fix bounds. Observed, not Asserted (EDR-VEX-01 D7).
	"alpine": value.TrustObserved,

	// Vendor statements about the vendor's own builds. Asserted is **not** a reliability
	// judgment — Red Hat is entirely trustworthy and is also the sole authority on their
	// own build, which is exactly why nothing can corroborate them. Classified at source
	// granularity and therefore conservatively: the feed carries vendor severity (closer to
	// a public record) alongside `not_affected` applicability (a judgment), and the weaker
	// of the two governs until per-statement classification exists.
	"redhat":  value.TrustAsserted,
	"vexfeed": value.TrustAsserted,
	"vex":     value.TrustAsserted,

	// A scanner's *inventory* would be Observed — rescanning an artifact reproduces it.
	// What Knowledge ingests from a scanner is its *verdict* ("this component is affected"),
	// which rests on the scanner's own matching heuristics; scanners routinely disagree on
	// the same artifact, so the verdict is a judgment, not an observation.
	"scanner": value.TrustAsserted,
}

// newTrustPolicy builds the injected source→trust-class policy.
func newTrustPolicy() domain.TrustPolicy { return domain.NewTrustPolicy(trustBySource) }

// shippedSources enumerates every source id Knowledge can record a Proposal under, DERIVED
// rather than hand-listed (TRUST-2).
//
// It was a literal slice maintained in the test, which meant adding a feed and forgetting both
// the trust table and the list still compiled — and the new source then failed closed to
// Asserted, silently. Safe, but wrong for a feed republishing a public record, whose
// conclusions would be needlessly kept out of policy auto-acceptance (and, since
// EDR-GOVERNANCE-01 D15, out of the one auto-accept rule that ships).
//
// Almost every source is a feed ACL, and the ACL registry already knows them all — registering
// an ACL is how a feed becomes reachable at all, so deriving from it makes classification
// impossible to skip. The only exception is the operator-uploaded VEX path, which is not a feed;
// it is named at its definition and added explicitly here.
func shippedSources() []string {
	return append(feed.NewRegistry().Sources(), app.VEXDocumentSource)
}
