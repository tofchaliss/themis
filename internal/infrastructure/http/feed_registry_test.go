package httpserver_test

import (
	"testing"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/infrastructure/config"
	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
)

func boolPtr(b bool) *bool { return &b }

func feedNames(fs []vexfeed.FeedSource) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Name()
	}
	return out
}

func contains(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func defaultVEXFeedConfig() config.VEXFeedConfig {
	return config.VEXFeedConfig{
		RHELVEXURL:   "https://rh/vex/",
		RHELCSAFURL:  "https://rh/advisories/",
		AlpineOSVURL: "https://osv/Alpine/all.zip",
		RockyOSVURL:  "https://osv/Rocky/all.zip",
		WolfiOSVURL:  "https://wolfi/security.json",
	}
}

func TestResolveVEXFeedsDefaults(t *testing.T) {
	overlay, correlation, warnings := httpserver.ResolveVEXFeeds(defaultVEXFeedConfig(), &vexfeed.HTTPFetcher{})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if got := feedNames(overlay); len(got) != 1 || got[0] != "rhel-vex" {
		t.Fatalf("overlay = %v, want [rhel-vex]", got)
	}
	corr := feedNames(correlation)
	for _, want := range []string{"alpine", "rocky", "wolfi", "rhel-csaf"} {
		if !contains(corr, want) {
			t.Fatalf("correlation %v missing %q", corr, want)
		}
	}
	if len(corr) != 4 {
		t.Fatalf("correlation = %v, want 4", corr)
	}
	// Built-in source types are constructed correctly.
	if _, ok := overlay[0].(vexfeed.CSAFDirectoryFeedSource); !ok {
		t.Fatalf("rhel-vex = %T, want CSAFDirectoryFeedSource", overlay[0])
	}
}

func TestResolveVEXFeedsDisableAndOverride(t *testing.T) {
	cfg := defaultVEXFeedConfig()
	cfg.Feeds = []config.FeedConfig{
		{Name: "rocky", Enabled: boolPtr(false)},           // disable a built-in
		{Name: "alpine", URL: "https://mirror/Alpine.zip"}, // override a built-in's URL
	}
	_, correlation, warnings := httpserver.ResolveVEXFeeds(cfg, &vexfeed.HTTPFetcher{})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	corr := feedNames(correlation)
	if contains(corr, "rocky") {
		t.Fatalf("rocky must be disabled: %v", corr)
	}
	var alpine vexfeed.ZipOSVFeedSource
	for _, f := range correlation {
		if z, ok := f.(vexfeed.ZipOSVFeedSource); ok && z.Name_ == "alpine" {
			alpine = z
		}
	}
	if alpine.URL != "https://mirror/Alpine.zip" {
		t.Fatalf("alpine URL not overridden: %q", alpine.URL)
	}
}

func TestResolveVEXFeedsCustomFeeds(t *testing.T) {
	cfg := defaultVEXFeedConfig()
	cfg.Feeds = []config.FeedConfig{
		{Name: "my-distro", Type: "zip-osv", URL: "https://x/all.zip", Ecosystem: "mydistro"}, // default class = correlation
		{Name: "my-vex", Type: "csaf-dir", Class: "overlay", URL: "https://y/vex/"},
		{Name: "my-url", Type: "url", URL: "https://z/sec.json"}, // kind defaults to osv
	}
	overlay, correlation, warnings := httpserver.ResolveVEXFeeds(cfg, &vexfeed.HTTPFetcher{})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	if !contains(feedNames(overlay), "my-vex") {
		t.Fatalf("custom overlay missing: %v", feedNames(overlay))
	}
	corr := feedNames(correlation)
	if !contains(corr, "my-distro") || !contains(corr, "my-url") {
		t.Fatalf("custom correlation feeds missing: %v", corr)
	}
	for _, f := range correlation {
		if u, ok := f.(vexfeed.URLFeedSource); ok && u.Name_ == "my-url" && u.Kind != "osv" {
			t.Fatalf("url feed kind = %q, want osv default", u.Kind)
		}
	}
}

func TestResolveVEXFeedsSkipsAndWarns(t *testing.T) {
	cfg := defaultVEXFeedConfig()
	cfg.Feeds = []config.FeedConfig{
		{Name: "bad-type", Type: "nope", URL: "https://x"}, // unknown type -> skip+warn
		{Name: "no-url", Type: "zip-osv"},                  // enabled, no URL -> skip+warn
		{Name: "", Type: "zip-osv", URL: "https://y"},      // no name -> warn
		{Name: "wolfi", Enabled: boolPtr(false)},           // disable built-in with URL
	}
	overlay, correlation, warnings := httpserver.ResolveVEXFeeds(cfg, &vexfeed.HTTPFetcher{})
	if len(warnings) != 3 {
		t.Fatalf("warnings = %v, want 3", warnings)
	}
	names := append(feedNames(overlay), feedNames(correlation)...)
	for _, gone := range []string{"bad-type", "no-url", "wolfi"} {
		if contains(names, gone) {
			t.Fatalf("%q should be absent: %v", gone, names)
		}
	}
}

func TestResolveVEXFeedsDeprecatedRHELURLFallback(t *testing.T) {
	cfg := config.VEXFeedConfig{RHELURL: "https://rh/advisories/"} // only the deprecated alias set
	_, correlation, _ := httpserver.ResolveVEXFeeds(cfg, &vexfeed.HTTPFetcher{})
	for _, f := range correlation {
		if c, ok := f.(vexfeed.CSAFDirectoryFeedSource); ok && c.Name_ == "rhel-csaf" {
			if c.URL != "https://rh/advisories/" {
				t.Fatalf("rhel-csaf URL = %q, want the rhel_url fallback", c.URL)
			}
			return
		}
	}
	t.Fatal("rhel-csaf feed not resolved from the deprecated rhel_url alias")
}
