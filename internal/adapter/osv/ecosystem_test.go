package osv_test

import (
	"testing"

	"github.com/themis-project/themis/internal/adapter/osv"
)

func TestMapEcosystem(t *testing.T) {
	tests := map[string]string{
		"npm":       "npm",
		"maven":     "Maven",
		"pypi":      "PyPI",
		"python":    "PyPI",
		"go":        "Go",
		"golang":    "Go",
		"nuget":     "NuGet",
		"gem":       "RubyGems",
		"rubygems":  "RubyGems",
		"deb":       "Debian",
		"debian":    "Debian",
		"apk":       "Alpine",
		"alpine":    "Alpine",
		"ubuntu":    "Ubuntu",
		"cargo":     "crates.io",
		"composer":  "Packagist",
		"packagist": "Packagist",
		"hex":       "Hex",
		"pub":       "Pub",
	}
	for in, want := range tests {
		got, ok := osv.MapEcosystem(in)
		if !ok || got != want {
			t.Fatalf("MapEcosystem(%q) = %q, %v want %q, true", in, got, ok, want)
		}
	}
	for _, unsupported := range []string{"", "rpm", "generic", "oci", "unknown"} {
		if _, ok := osv.MapEcosystem(unsupported); ok {
			t.Fatalf("MapEcosystem(%q) should be unsupported", unsupported)
		}
	}
}
