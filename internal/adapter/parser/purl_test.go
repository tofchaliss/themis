package parser

import "testing"

func TestEcosystemFromPURL(t *testing.T) {
	tests := []struct {
		purl      string
		ecosystem string
		ok        bool
	}{
		{purl: "pkg:npm/lodash@4.17.21", ecosystem: "npm", ok: true},
		{purl: "pkg:maven/org.apache/commons@1.0", ecosystem: "maven", ok: true},
		{purl: "pkg:npm@1.0.0", ecosystem: "npm", ok: true},
		{purl: "not-a-purl", ok: false},
		{purl: "pkg:", ok: false},
		{purl: "pkg:@bad", ok: false},
	}
	for _, tt := range tests {
		got, ok := ecosystemFromPURL(tt.purl)
		if ok != tt.ok || got != tt.ecosystem {
			t.Fatalf("ecosystemFromPURL(%q) = (%q, %v), want (%q, %v)", tt.purl, got, ok, tt.ecosystem, tt.ok)
		}
	}
}

func TestNameVersionFromPURL(t *testing.T) {
	name, version := nameVersionFromPURL("pkg:npm/lodash@4.17.21")
	if name != "lodash" || version != "4.17.21" {
		t.Fatalf("nameVersionFromPURL() = (%q, %q)", name, version)
	}
	name, version = nameVersionFromPURL("pkg:npm/lodash")
	if name != "lodash" || version != "" {
		t.Fatalf("nameVersionFromPURL(no version) = (%q, %q)", name, version)
	}
	name, version = nameVersionFromPURL("pkg:npm")
	if name != "" || version != "" {
		t.Fatalf("nameVersionFromPURL(no path) = (%q, %q)", name, version)
	}
	name, version = nameVersionFromPURL("pkg:npm/")
	if name != "" || version != "" {
		t.Fatalf("nameVersionFromPURL(empty path) = (%q, %q)", name, version)
	}
	name, version = nameVersionFromPURL("bad")
	if name != "" || version != "" {
		t.Fatalf("nameVersionFromPURL(bad) = (%q, %q)", name, version)
	}
	// Percent-encoded segments are decoded ("%2B%2B" → "++").
	name, version = nameVersionFromPURL("pkg:rpm/rocky/libstdc%2B%2B@8.5.0-28.el8_10?arch=x86_64")
	if name != "rocky/libstdc++" || version != "8.5.0-28.el8_10" {
		t.Fatalf("nameVersionFromPURL(encoded) = (%q, %q)", name, version)
	}
	// Invalid percent-encoding falls back to the raw segment (no panic, no error).
	name, version = nameVersionFromPURL("pkg:rpm/rocky/bad%zz@1%gg")
	if name != "rocky/bad%zz" || version != "1%gg" {
		t.Fatalf("nameVersionFromPURL(invalid encoding) = (%q, %q)", name, version)
	}
}

func TestBuildPURL(t *testing.T) {
	if got := buildPURL("npm", "lodash", "1.0.0"); got != "pkg:npm/lodash@1.0.0" {
		t.Fatalf("buildPURL() = %q", got)
	}
	if got := buildPURL("", "lodash", "1.0.0"); got != "" {
		t.Fatalf("buildPURL(empty ecosystem) = %q", got)
	}
}
