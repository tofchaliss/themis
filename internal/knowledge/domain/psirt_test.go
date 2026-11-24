package domain_test

import (
	"fmt"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// EDR-PSIRT-01 Q1 (name match): both sides compare in one spelling.
func TestNormalizeProductName(t *testing.T) {
	for in, want := range map[string]string{
		" HTTP_Server ": "http-server",
		"lib foo":       "lib-foo",
		"openssl":       "openssl",
		"":              "",
	} {
		if got := domain.NormalizeProductName(in); got != want {
			t.Errorf("NormalizeProductName(%q) = %q, want %q", in, got, want)
		}
	}
}

// NVD's CPE products are taken whole; a CNA entry "vendor:product[:package]" gives its product
// and package, the vendor only when it is the whole entry; short names and "n/a" never match.
func TestAffectedNames(t *testing.T) {
	got := domain.AffectedNames(
		[]string{"libxml2", "go", "Http_Server"},
		[]string{"example:libfoo:libfoo-core", "lonevendor", "acme:n/a", "acme:ui"},
	)
	if fmt.Sprint(got) != "[http-server libfoo libfoo-core libxml2 lonevendor]" {
		t.Errorf("AffectedNames = %v", got)
	}
	if got := domain.AffectedNames(nil, nil); len(got) != 0 {
		t.Errorf("no input = %v", got)
	}
}

// A component matches on its name, its source package, or its last path segment; one row per
// component, and nothing matches on an empty side.
func TestMatchComponents(t *testing.T) {
	comps := []domain.ComponentRef{
		{Name: "openssl-libs", Source: "openssl"},
		{Name: "golang.org/x/net"},
		{Name: "libxml2", Source: "libxml2"},
		{Name: "unrelated"},
	}
	got := domain.MatchComponents([]string{"openssl", "net", "libxml2", "xy"}, comps)
	if fmt.Sprint(got) != "[{golang.org/x/net net} {libxml2 libxml2} {openssl-libs openssl}]" {
		t.Errorf("MatchComponents = %v", got)
	}
	// Two affected names hit one component: one row, the first name in sorted order reported.
	two := domain.MatchComponents([]string{"zlib", "zlib-ng"}, []domain.ComponentRef{{Name: "zlib-ng", Source: "zlib"}})
	if fmt.Sprint(two) != "[{zlib-ng zlib}]" {
		t.Errorf("two names = %v", two)
	}
	if domain.MatchComponents(nil, comps) != nil || domain.MatchComponents([]string{"openssl"}, nil) != nil {
		t.Error("an empty side matches nothing")
	}
}
