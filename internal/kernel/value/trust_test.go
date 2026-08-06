package value

import "testing"

func TestTrustClass_Valid(t *testing.T) {
	for _, c := range []TrustClass{TrustObserved, TrustAsserted, TrustInferred} {
		if !c.Valid() {
			t.Fatalf("expected %q valid", c)
		}
	}
	for _, c := range []TrustClass{"", "OBSERVED", "trusted", "unknown"} {
		if c.Valid() {
			t.Fatalf("expected %q invalid", c)
		}
	}
}

func TestTrustClass_String(t *testing.T) {
	if got := TrustAsserted.String(); got != "asserted" {
		t.Fatalf("String() = %q, want %q", got, "asserted")
	}
}

// rank orders by risk, and anything unrecognized must rank at the top so a malformed
// class can never be mistaken for a trusted one.
func TestTrustClass_rank(t *testing.T) {
	if TrustObserved.rank() >= TrustAsserted.rank() || TrustAsserted.rank() >= TrustInferred.rank() {
		t.Fatal("expected Observed < Asserted < Inferred by risk")
	}
	if TrustClass("garbage").rank() != TrustInferred.rank() {
		t.Fatal("expected an unrecognized class to rank as high-risk")
	}
}

func TestMaxTrust(t *testing.T) {
	tests := []struct {
		name  string
		first TrustClass
		rest  []TrustClass
		want  TrustClass
	}{
		{"single", TrustObserved, nil, TrustObserved},
		{"all observed", TrustObserved, []TrustClass{TrustObserved}, TrustObserved},
		{"asserted dominates observed", TrustObserved, []TrustClass{TrustAsserted}, TrustAsserted},
		{"order does not matter", TrustAsserted, []TrustClass{TrustObserved}, TrustAsserted},
		{"inferred dominates all", TrustObserved, []TrustClass{TrustAsserted, TrustInferred}, TrustInferred},
		{"inferred first", TrustInferred, []TrustClass{TrustObserved, TrustObserved}, TrustInferred},
		{"invalid normalizes to inferred", TrustClass("garbage"), nil, TrustInferred},
		{"invalid in rest normalizes", TrustObserved, []TrustClass{TrustClass("garbage")}, TrustInferred},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MaxTrust(tc.first, tc.rest...); got != tc.want {
				t.Fatalf("MaxTrust(%q, %v) = %q, want %q", tc.first, tc.rest, got, tc.want)
			}
		})
	}
}

// The laundering case EDR-TRUST-01 T1/T3 exist to close: a deterministic rule consuming
// one AI-derived fact yields an Inferred conclusion, however much Observed evidence it
// also used. Producer-based classification cannot see this — it asks who spoke last.
func TestMaxTrust_DeterministicRuleCannotLaunderInferredEvidence(t *testing.T) {
	got := MaxTrust(TrustObserved, TrustObserved, TrustObserved, TrustInferred)
	if got != TrustInferred {
		t.Fatalf("MaxTrust with one Inferred input = %q, want %q — determinism must launder nothing", got, TrustInferred)
	}
}
