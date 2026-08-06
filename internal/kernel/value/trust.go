package value

// TrustClass is how much a fact is worth, decided by one question: **can this be
// re-derived, or must someone be believed?** It is a property of *evidence* — never of
// the rule, model, or service that produced a conclusion from it (EDR-TRUST-01 T1).
//
// The criterion is *derivable vs declared*, not who the fact is about and not how it
// reached us. Transport decides nothing: an affected range and a vendor's "not affected"
// may arrive by the identical HTTP fetch of a JSON document from the same server. What
// separates them is that the range is a public record anyone can check, while the
// "not affected" is a judgment nothing can re-run.
//
// Two calibrating examples, because this is the line implementers get wrong:
//
//   - An SBOM component list is Observed. It is a claim about our own product, yet
//     rescanning the artifact reproduces it — a tool derived it, nobody asserted it.
//   - A vendor's "not affected" is Asserted. Not because the vendor is unreliable, but
//     because they are the sole authority on their own build, so nothing can check them.
//     That is structural, not a data-quality judgment.
//
// Self-assertion is not observation: a claim our own operators type is Asserted, while
// the same claim backed by a signed artifact Themis holds becomes Observed. That gap is
// the point — it names exactly which artifact is worth going to collect.
type TrustClass string

const (
	// TrustObserved is reproducible: mechanically derivable from an artifact Themis holds,
	// or a public record independent parties publish. Re-run the derivation, same answer.
	TrustObserved TrustClass = "observed"
	// TrustAsserted is not reproducible: a declaration or judgment Themis cannot re-derive.
	// Trust rests on the declarer, who is recorded along with when they said it.
	TrustAsserted TrustClass = "asserted"
	// TrustInferred is the output of non-deterministic reasoning — a judgment, not an
	// observation, and not re-derivable even in principle. Constitutionally barred from
	// automatic acceptance under any policy (EDR-TRUST-01 T4).
	TrustInferred TrustClass = "inferred"
)

// Valid reports whether c is a recognized trust class.
func (c TrustClass) Valid() bool {
	switch c {
	case TrustObserved, TrustAsserted, TrustInferred:
		return true
	default:
		return false
	}
}

// String returns the class label.
func (c TrustClass) String() string { return string(c) }

// rank orders the classes by risk: Observed < Asserted < Inferred. An unrecognized value
// ranks highest, so a malformed class can never be mistaken for a trusted one.
func (c TrustClass) rank() int {
	switch c {
	case TrustObserved:
		return 0
	case TrustAsserted:
		return 1
	default: // TrustInferred and anything unrecognized
		return 2
	}
}

// MaxTrust returns the highest-risk class among the given ones — the trust a conclusion
// inherits from the evidence it depended on (EDR-TRUST-01 T3).
//
// Propagation is monotonic: a conclusion is never more trusted than its weakest input,
// and no step may raise a class. Only new, better-classed evidence yields a
// better-classed conclusion, and that is a *new* conclusion rather than a promotion of
// the old one. Monotonicity is what makes the model auditable — if any step could raise
// trust, "why was this trusted?" would have no stable answer.
//
// The signature requires at least one class deliberately. A variadic-only signature would
// return the lowest-risk class for an empty argument list, so a bug that passed no
// evidence would silently produce the most trusted answer — precisely the failure this
// decision exists to prevent. An unrecognized input is treated as (and normalized to)
// TrustInferred, so the result is always a valid class.
func MaxTrust(first TrustClass, rest ...TrustClass) TrustClass {
	worst := first
	for _, c := range rest {
		if c.rank() > worst.rank() {
			worst = c
		}
	}
	if !worst.Valid() {
		return TrustInferred
	}
	return worst
}
