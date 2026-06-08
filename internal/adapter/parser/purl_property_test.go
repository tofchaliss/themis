package parser

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/testutil/gen"
)

func TestPURLRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		eco := gen.Ecosystem(t)
		name := gen.PkgName(t)
		version := gen.PkgVersion(t)

		withVersion := buildPURL(eco, name, version)
		gotEco, ok := ecosystemFromPURL(withVersion)
		if !ok || gotEco != eco {
			t.Fatalf("ecosystem round-trip: purl=%q got=%q ok=%v want=%q", withVersion, gotEco, ok, eco)
		}
		gotName, gotVersion := nameVersionFromPURL(withVersion)
		if gotName != name || gotVersion != version {
			t.Fatalf("name/version round-trip: purl=%q got=(%q,%q) want=(%q,%q)",
				withVersion, gotName, gotVersion, name, version)
		}

		noVersion := buildPURL(eco, name, "")
		if strings.Contains(noVersion, "@") {
			t.Fatalf("versionless purl should have no '@': %q", noVersion)
		}
		gotEco2, ok2 := ecosystemFromPURL(noVersion)
		if !ok2 || gotEco2 != eco {
			t.Fatalf("ecosystem round-trip (no version): purl=%q got=%q ok=%v want=%q", noVersion, gotEco2, ok2, eco)
		}
		gotName2, gotVersion2 := nameVersionFromPURL(noVersion)
		if gotName2 != name || gotVersion2 != "" {
			t.Fatalf("name round-trip (no version): purl=%q got=(%q,%q) want=(%q,\"\")",
				noVersion, gotName2, gotVersion2, name)
		}
	})
}

// TestPURLParseNoPanicProperty asserts the parse helpers never panic and respect
// the pkg: prefix invariant for arbitrary input.
func TestPURLParseNoPanicProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "arbitrary")
		eco, ok := ecosystemFromPURL(s)
		if ok && !strings.HasPrefix(s, "pkg:") {
			t.Fatalf("ecosystemFromPURL returned ok for non-pkg input %q", s)
		}
		if ok && eco == "" {
			t.Fatalf("ecosystemFromPURL returned ok with empty ecosystem for %q", s)
		}
		// Must not panic.
		_, _ = nameVersionFromPURL(s)
	})
}
