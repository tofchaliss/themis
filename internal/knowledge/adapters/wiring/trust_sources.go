package wiring

import (
	"github.com/themis-project/themis/internal/kernel/value"
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
	"epss":      value.TrustObserved,
	"kev":       value.TrustObserved,
	"epsskev":   value.TrustObserved,
	"exploitdb": value.TrustObserved,

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
	"scanner":        value.TrustAsserted,
	"scanner-report": value.TrustAsserted,
}

// newTrustPolicy builds the injected source→trust-class policy.
func newTrustPolicy() domain.TrustPolicy { return domain.NewTrustPolicy(trustBySource) }
