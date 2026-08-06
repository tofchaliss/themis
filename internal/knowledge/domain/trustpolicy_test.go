package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The three calibration cases from EDR-TRUST-01 T2. They are the line implementers get
// wrong, so they are asserted explicitly rather than left to the table's comments.
func TestTrustPolicy_ClassOf_CalibrationCases(t *testing.T) {
	p := domain.NewTrustPolicy(map[string]value.TrustClass{
		"osv":    value.TrustObserved, // a public record — re-fetch reproduces it
		"redhat": value.TrustAsserted, // a judgment about the vendor's own build
		"ai":     value.TrustInferred, // non-deterministic reasoning
	})

	for _, tc := range []struct {
		source string
		want   value.TrustClass
	}{
		{"osv", value.TrustObserved},
		{"redhat", value.TrustAsserted},
		{"ai", value.TrustInferred},
	} {
		if got := p.ClassOf(tc.source); got != tc.want {
			t.Fatalf("ClassOf(%q) = %q, want %q", tc.source, got, tc.want)
		}
	}
}

func TestTrustPolicy_ClassOf_IsCaseAndSpaceInsensitive(t *testing.T) {
	p := domain.NewTrustPolicy(map[string]value.TrustClass{"  OSV ": value.TrustObserved})
	for _, s := range []string{"osv", "OSV", " osv  "} {
		if got := p.ClassOf(s); got != value.TrustObserved {
			t.Fatalf("ClassOf(%q) = %q, want %q", s, got, value.TrustObserved)
		}
	}
}

// An unregistered source fails closed to Asserted — never Observed, which is the class
// deterministic auto-acceptance rests on. Asserted rather than Inferred is deliberate:
// Inferred means "a model produced this", so labelling an unclassified feed Inferred
// would be a lie that corrupts the vocabulary for the sake of a risk level.
func TestTrustPolicy_ClassOf_UnknownSourceFailsClosedToAsserted(t *testing.T) {
	p := domain.NewTrustPolicy(map[string]value.TrustClass{"osv": value.TrustObserved})
	for _, s := range []string{"never-registered", "", "   "} {
		if got := p.ClassOf(s); got != value.TrustAsserted {
			t.Fatalf("ClassOf(%q) = %q, want %q (fail closed)", s, got, value.TrustAsserted)
		}
	}
}

// A malformed table entry must not leak through as a trusted class.
func TestTrustPolicy_ClassOf_InvalidClassInTableFailsClosed(t *testing.T) {
	p := domain.NewTrustPolicy(map[string]value.TrustClass{"broken": value.TrustClass("garbage")})
	if got := p.ClassOf("broken"); got != value.TrustAsserted {
		t.Fatalf("ClassOf(broken) = %q, want %q", got, value.TrustAsserted)
	}
}

func TestTrustPolicy_NilTableClassifiesEverythingAsserted(t *testing.T) {
	if got := domain.NewTrustPolicy(nil).ClassOf("osv"); got != value.TrustAsserted {
		t.Fatalf("ClassOf on empty policy = %q, want %q", got, value.TrustAsserted)
	}
}
