package value_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func TestContentFingerprint_KnownVector(t *testing.T) {
	// SHA-256("abc") — a standard test vector.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	got := value.NewContentFingerprint([]byte("abc"))
	if got.String() != want {
		t.Fatalf("fingerprint = %q, want %q", got.String(), want)
	}
	if got.IsZero() {
		t.Fatal("constructed fingerprint reports IsZero")
	}
}

func TestContentFingerprint_Determinism_Equality(t *testing.T) {
	a := value.NewContentFingerprint([]byte("same bytes"))
	b := value.NewContentFingerprint([]byte("same bytes"))
	c := value.NewContentFingerprint([]byte("other bytes"))

	if !a.Equal(b) {
		t.Error("identical bytes produced unequal fingerprints")
	}
	if a.Equal(c) {
		t.Error("different bytes produced equal fingerprints")
	}
}

func TestContentFingerprint_Zero(t *testing.T) {
	var zero value.ContentFingerprint
	if !zero.IsZero() {
		t.Error("zero value should report IsZero")
	}
	if zero.String() != "" {
		t.Errorf("zero String = %q, want empty", zero.String())
	}
}

func TestParseContentFingerprint(t *testing.T) {
	valid := value.NewContentFingerprint([]byte("roundtrip")).String()
	got, err := value.ParseContentFingerprint(valid)
	if err != nil {
		t.Fatalf("parse valid: %v", err)
	}
	if got.String() != valid {
		t.Fatalf("round-trip = %q, want %q", got.String(), valid)
	}

	for name, in := range map[string]string{
		"empty":     "",
		"tooShort":  "abc123",
		"uppercase": "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
		"nonHex":    "zz7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	} {
		if _, err := value.ParseContentFingerprint(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNewPURL(t *testing.T) {
	p, err := value.NewPURL("  pkg:deb/debian/openssl@3.0.11  ")
	if err != nil {
		t.Fatalf("valid purl: %v", err)
	}
	if p.String() != "pkg:deb/debian/openssl@3.0.11" {
		t.Fatalf("purl not trimmed/canonical: %q", p.String())
	}
	if p.IsZero() {
		t.Error("constructed purl reports IsZero")
	}

	for name, in := range map[string]string{
		"empty":        "",
		"whitespace":   "   ",
		"missingSchem": "deb/debian/openssl@3.0.11",
		"schemeOnly":   "pkg:",
	} {
		if _, err := value.NewPURL(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestPURL_Equal_Zero(t *testing.T) {
	a, _ := value.NewPURL("pkg:npm/left-pad@1.0.0")
	b, _ := value.NewPURL("pkg:npm/left-pad@1.0.0")
	c, _ := value.NewPURL("pkg:npm/right-pad@1.0.0")
	if !a.Equal(b) {
		t.Error("equal purls reported unequal")
	}
	if a.Equal(c) {
		t.Error("different purls reported equal")
	}

	var zero value.PURL
	if !zero.IsZero() {
		t.Error("zero purl should report IsZero")
	}
	if zero.String() != "" {
		t.Errorf("zero purl String = %q, want empty", zero.String())
	}
}
