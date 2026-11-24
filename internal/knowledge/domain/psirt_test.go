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

// AffectedRefs keeps the vendor beside each product or package; a bare entry has none, and an
// "n/a" vendor reads as none.
func TestAffectedRefs(t *testing.T) {
	got := domain.AffectedRefs([]string{"Go-OpenAPI:runtime", "example:libfoo:libfoo-core", "lonevendor", "n/a:libbar", "acme:ui", "acme:n/a", "example:libfoo"})
	if fmt.Sprint(got) != "[{ libbar} {example libfoo} {example libfoo-core} { lonevendor} {go-openapi runtime}]" {
		t.Errorf("AffectedRefs = %v", got)
	}
	if got := domain.AffectedRefs(nil); len(got) != 0 {
		t.Errorf("no input = %v", got)
	}
}

func refs(entries ...string) []domain.AffectedRef { return domain.AffectedRefs(entries) }

// A component matches on its name or source package; a path's last segment matches only with
// the vendor among its other segments; one row per component, nothing on an empty side.
func TestMatchComponents(t *testing.T) {
	comps := []domain.ComponentRef{
		{Name: "openssl-libs", Source: "openssl"},
		{Name: "golang.org/x/net"},
		{Name: "github.com/go-openapi/runtime"},
		{Name: "libxml2", Source: "libxml2"},
		{Name: "unrelated"},
	}
	got := domain.MatchComponents(refs("openssl", "golang:net", "xmlsoft:libxml2", "xy", "othervendor:runtime", "runtime"), comps)
	if fmt.Sprint(got) != "[{golang.org/x/net golang:net} {libxml2 libxml2} {openssl-libs openssl}]" {
		t.Errorf("MatchComponents = %v", got)
	}
	// The VM case (2026-11-24): another vendor's "runtime" never hits the Go module; its own does.
	if got := domain.MatchComponents(refs("othervendor:runtime"), comps); len(got) != 0 {
		t.Errorf("another vendor's runtime = %v", got)
	}
	if got := domain.MatchComponents(refs("go-openapi:runtime"), comps); fmt.Sprint(got) != "[{github.com/go-openapi/runtime go-openapi:runtime}]" {
		t.Errorf("its own vendor = %v", got)
	}
	// The whole path as the product matches like any name.
	if got := domain.MatchComponents(refs("golang.org/x/net"), comps); fmt.Sprint(got) != "[{golang.org/x/net golang.org/x/net}]" {
		t.Errorf("whole path = %v", got)
	}
	// Two affected names hit one component: one row, the first name in sorted order reported.
	two := domain.MatchComponents(refs("zlib", "zlib-ng"), []domain.ComponentRef{{Name: "zlib-ng", Source: "zlib"}})
	if fmt.Sprint(two) != "[{zlib-ng zlib}]" {
		t.Errorf("two names = %v", two)
	}
	if domain.MatchComponents(nil, comps) != nil || domain.MatchComponents(refs("openssl"), nil) != nil {
		t.Error("an empty side matches nothing")
	}
	if got := domain.MatchComponents([]domain.AffectedRef{{Product: "ab"}}, comps); len(got) != 0 {
		t.Errorf("a short ref = %v", got)
	}
}
