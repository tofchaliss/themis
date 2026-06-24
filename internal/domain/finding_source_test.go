package domain

import "testing"

func TestDefaultFindingSource(t *testing.T) {
	if got := DefaultFindingSource(""); got != FindingSourceCatalog {
		t.Fatalf("empty → %q, want %q", got, FindingSourceCatalog)
	}
	if got := DefaultFindingSource(FindingSourceOSV); got != FindingSourceOSV {
		t.Fatalf("set → %q, want %q", got, FindingSourceOSV)
	}
}

func TestFindingSourcePrecedence(t *testing.T) {
	// Distro packages: distro feeds outrank OSV.dev and NVD.
	if FindingSourcePrecedence("apk", FindingSourceDistroOSV) <= FindingSourcePrecedence("apk", FindingSourceOSV) {
		t.Fatal("distro_osv must outrank osv for apk")
	}
	if FindingSourcePrecedence("rpm", FindingSourceRHSA) <= FindingSourcePrecedence("rpm", FindingSourceNVD) {
		t.Fatal("rhsa must outrank nvd for rpm")
	}
	// OSV.dev outranks NVD for application ecosystems.
	if FindingSourcePrecedence("npm", FindingSourceOSV) <= FindingSourcePrecedence("npm", FindingSourceNVD) {
		t.Fatal("osv must outrank nvd for npm")
	}
	// For application ecosystems the distro-only feeds drop to a low rank.
	if FindingSourcePrecedence("npm", FindingSourceDistroOSV) >= FindingSourcePrecedence("npm", FindingSourceOSV) {
		t.Fatal("distro_osv must not outrank osv for npm")
	}
	if FindingSourcePrecedence("npm", FindingSourceRHSA) >= FindingSourcePrecedence("npm", FindingSourceOSV) {
		t.Fatal("rhsa must not outrank osv for npm")
	}
	// Known sources all outrank catalog/legacy/unknown.
	for _, s := range []string{FindingSourceOSV, FindingSourceNVD, FindingSourceScanner} {
		if FindingSourcePrecedence("npm", s) <= FindingSourcePrecedence("npm", FindingSourceCatalog) {
			t.Fatalf("%q must outrank catalog", s)
		}
	}
	if FindingSourcePrecedence("npm", FindingSourceCatalog) <= FindingSourcePrecedence("npm", "totally-unknown") {
		t.Fatal("catalog must outrank an unknown source")
	}
}
