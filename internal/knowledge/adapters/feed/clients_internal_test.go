package feed

import (
	"net/http"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
)

func TestConstructors_Defaults(t *testing.T) {
	o := NewOSVClient("", nil)
	if o.baseURL != OSVBaseURL || o.http != http.DefaultClient {
		t.Errorf("OSV defaults: baseURL=%q http=%v", o.baseURL, o.http == http.DefaultClient)
	}
	n := NewNVDClient("", "", nil)
	if n.baseURL != NVDBaseURL || n.http != http.DefaultClient {
		t.Errorf("NVD defaults: baseURL=%q http=%v", n.baseURL, n.http == http.DefaultClient)
	}
	// Trailing slashes are trimmed so path joins are clean.
	if got := NewOSVClient("http://x/", nil).baseURL; got != "http://x" {
		t.Errorf("trailing slash not trimmed: %q", got)
	}
}

func TestExtractNVDCVSS_V2TopLevelSeverity(t *testing.T) {
	m := nvdMetrics{V2: []nvdMetric{{Type: "Primary", BaseSeverity: "HIGH", CVSSData: struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	}{BaseScore: 7.5, VectorString: "AV:N"}}}}
	sev, score, vec, found := extractNVDCVSS(m)
	if !found || sev != "HIGH" || score != 7.5 || vec != "AV:N" {
		t.Errorf("v2: sev=%s score=%.1f vec=%s found=%v, want HIGH/7.5/AV:N/true", sev, score, vec, found)
	}
}

func TestExtractNVDCVSS_None(t *testing.T) {
	if _, _, _, found := extractNVDCVSS(nvdMetrics{}); found {
		t.Error("empty metrics should report found=false")
	}
}

func TestNVDVersionFacts(t *testing.T) {
	configs := []nvdConfig{{Nodes: []struct {
		CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	}{{CPEMatch: []nvdCPEMatch{
		{Vulnerable: true, VersionStartIncluding: "1.0", VersionEndExcluding: "2.0"},
		{Vulnerable: true, VersionStartIncluding: "1.0", VersionEndExcluding: "2.0"}, // dup → collapsed
		{Vulnerable: false, VersionEndExcluding: "9.9"},                              // not vulnerable → ignored
		{Vulnerable: true, VersionStartExcluding: "3.0", VersionEndIncluding: "4.0"},
	}}}}}
	affected, fixed := nvdVersionFacts(configs)
	if len(affected) != 2 || affected[0] != ">=1.0,<2.0" || affected[1] != ">3.0,<=4.0" {
		t.Errorf("affected = %v", affected)
	}
	if len(fixed) != 1 || fixed[0] != "2.0" {
		t.Errorf("fixed = %v", fixed)
	}
}

func TestCPERange(t *testing.T) {
	cases := map[string]nvdCPEMatch{
		">=1.0,<2.0": {VersionStartIncluding: "1.0", VersionEndExcluding: "2.0"},
		">1.0,<=2.0": {VersionStartExcluding: "1.0", VersionEndIncluding: "2.0"},
		">=1.0":      {VersionStartIncluding: "1.0"},
		"<2.0":       {VersionEndExcluding: "2.0"},
		"":           {},
	}
	for want, m := range cases {
		if got := cpeRange(m); got != want {
			t.Errorf("cpeRange(%+v) = %q, want %q", m, got, want)
		}
	}
}

func TestParseNVDTime(t *testing.T) {
	if got := parseNVDTime("2026-07-20T10:00:00.000"); got.Year() != 2026 || got.Hour() != 10 {
		t.Errorf("nvd layout: %v", got)
	}
	if got := parseNVDTime("2026-07-20T10:00:00Z"); got.Year() != 2026 { // RFC3339 fallback
		t.Errorf("rfc3339 fallback: %v", got)
	}
	// Empty and garbage both fall back to ~now (a valid, non-zero time).
	for _, s := range []string{"", "not-a-time"} {
		if got := parseNVDTime(s); time.Since(got) > time.Minute {
			t.Errorf("fallback-to-now(%q) = %v", s, got)
		}
	}
}

func TestOSVEcosystem(t *testing.T) {
	comp := func(purl, eco string) app.InventoryComponent {
		return app.InventoryComponent{PURL: purl, Ecosystem: eco}
	}
	cases := []struct {
		purl, eco, want string
	}{
		{"pkg:pypi/x@1", "", "PyPI"},
		{"pkg:maven/g/a@1", "", "Maven"},
		{"pkg:npm/x@1", "", "npm"},
		{"pkg:golang/x@1", "", "Go"},
		{"pkg:gem/x@1", "", "RubyGems"},
		{"pkg:cargo/x@1", "", "crates.io"},
		{"pkg:nuget/x@1", "", "NuGet"},
		{"pkg:composer/v/x@1", "", "Packagist"},
		{"pkg:hex/x@1", "", "Hex"},
		{"pkg:pub/x@1", "", "Pub"},
		{"pkg:rpm/rocky/x@1", "", ""},  // distro → skip
		{"pkg:apk/alpine/x@1", "", ""}, // distro → skip
		{"", "PyPI", "PyPI"},           // fallback to ecosystem label
		{"", "golang", "Go"},           // fallback synonym
		{"", "somethingelse", ""},      // unknown → skip
	}
	for _, c := range cases {
		if got := osvEcosystem(comp(c.purl, c.eco)); got != c.want {
			t.Errorf("osvEcosystem(%q,%q) = %q, want %q", c.purl, c.eco, got, c.want)
		}
	}
}

func TestOSVPackageName(t *testing.T) {
	cases := []struct {
		purl, name, want string
	}{
		{"pkg:maven/io.prometheus/prom@1", "prom", "io.prometheus:prom"},
		{"pkg:npm/@scope/pkg@1", "pkg", "@scope/pkg"},
		{"pkg:pypi/urllib3@1", "urllib3", "urllib3"},
		{"", "fallback", "fallback"}, // no PURL → component Name
	}
	for _, c := range cases {
		got := osvPackageName(app.InventoryComponent{PURL: c.purl, Name: c.name})
		if got != c.want {
			t.Errorf("osvPackageName(%q,%q) = %q, want %q", c.purl, c.name, got, c.want)
		}
	}
}

func TestPURLHelpers(t *testing.T) {
	if purlType("not-a-purl") != "" || purlType("pkg:pypi") != "" {
		t.Error("purlType should be empty for non-purl / typeless")
	}
	ns, name := purlNamespaceName("pkg:maven/io.prometheus/prom@1.2?arch=x")
	if ns != "io.prometheus" || name != "prom" {
		t.Errorf("purlNamespaceName = %q/%q", ns, name)
	}
	if ns, name := purlNamespaceName("pkg:pypi/urllib3@1"); ns != "" || name != "urllib3" {
		t.Errorf("bare name = %q/%q", ns, name)
	}
	if _, name := purlNamespaceName("not-a-purl"); name != "" {
		t.Errorf("non-purl name = %q", name)
	}
}

func TestTruncateForError(t *testing.T) {
	if got := truncateForError([]byte("short")); got != "short" {
		t.Errorf("short = %q", got)
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'a'
	}
	if got := truncateForError(long); len(got) <= 200 || got[len(got)-3:] != "…" {
		t.Errorf("long truncation failed: len=%d", len(got))
	}
}
