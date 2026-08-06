package value

import (
	"testing"

	"pgregory.net/rapid"
)

// trustToken draws any trust class plus an unrecognized value, so the safety properties
// are exercised on malformed input too — that is exactly where a silent downgrade to a
// trusted class would hide.
func trustToken(t *rapid.T) TrustClass {
	return rapid.SampledFrom([]TrustClass{
		TrustObserved, TrustAsserted, TrustInferred, TrustClass("garbage"), TrustClass(""),
	}).Draw(t, "class")
}

// The invariant the whole trust model rests on (T3): a conclusion is never more trusted
// than its weakest input. If this can be broken, "why was this trusted?" has no stable
// answer and the constitutional bar on Inferred (T4) can be bypassed by construction.
func TestMaxTrustNeverLowersRiskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := trustToken(t), trustToken(t)
		got := MaxTrust(a, b)
		if got.rank() < a.rank() || got.rank() < b.rank() {
			t.Fatalf("monotonicity broken: MaxTrust(%q,%q)=%q ranks below an input", a, b, got)
		}
	})
}

// Evidence is a set, not a sequence — the order facts happen to be collected in must not
// change what a conclusion is worth.
func TestMaxTrustCommutativeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := trustToken(t), trustToken(t)
		if got, mirror := MaxTrust(a, b), MaxTrust(b, a); got != mirror {
			t.Fatalf("commutativity broken: MaxTrust(%q,%q)=%q vs MaxTrust(%q,%q)=%q", a, b, got, b, a, mirror)
		}
	})
}

// Propagation must survive being applied in stages: folding evidence in two steps has to
// agree with folding it in one, or a multi-hop pipeline could land on a different class
// than a single-hop one.
func TestMaxTrustAssociativeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b, c := trustToken(t), trustToken(t), trustToken(t)
		left := MaxTrust(MaxTrust(a, b), c)
		right := MaxTrust(a, MaxTrust(b, c))
		if left != right {
			t.Fatalf("associativity broken for (%q,%q,%q): %q vs %q", a, b, c, left, right)
		}
	})
}

// Re-observing the same fact adds no risk and removes none.
func TestMaxTrustIdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := trustToken(t)
		if got, want := MaxTrust(a, a), MaxTrust(a); got != want {
			t.Fatalf("idempotence broken: MaxTrust(%q,%q)=%q, MaxTrust(%q)=%q", a, a, got, a, want)
		}
	})
}

// The result is always a class the rest of the system can branch on — a malformed input
// must normalize rather than propagate, or downstream switches fall through unpredictably.
func TestMaxTrustAlwaysReturnsValidProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := trustToken(t), trustToken(t)
		if got := MaxTrust(a, b); !got.Valid() {
			t.Fatalf("MaxTrust(%q,%q) returned invalid class %q", a, b, got)
		}
	})
}
