package httpserver

import (
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/infrastructure/config"
)

// Feed registry (themis-feed-registry). The vendor feed set used to be hardcoded in
// DI: operators could override each URL but could not add, remove, or disable a feed.
// ResolveVEXFeeds turns the built-in defaults (derived from the legacy *_url fields,
// so existing configs are unchanged) plus the user `vexfeed.feeds` delta list into
// the two runtime feed lists — the VEX overlay (true Red Hat CSAF VEX) and the
// correlation sources (distro OSV + RHSA advisories).

// feedClassOverlay feeds apply as the VEX overlay; feedClassCorrelation feeds are
// correlation sources (severity + fixed-version ranges).
const (
	feedClassOverlay     = "overlay"
	feedClassCorrelation = "correlation"
)

// feedSpec is the merge-friendly intermediate form of a feed: the built-in defaults
// and the user deltas are reconciled as specs, then constructed into FeedSources.
type feedSpec struct {
	name    string
	typ     string // csaf-dir | zip-osv | url
	class   string // overlay | correlation
	url     string
	kind    string // for typ=url: csaf | osv
	enabled bool
}

// ResolveVEXFeeds builds the overlay and correlation feed lists from the config. It
// starts from the built-in defaults, applies the user delta list (merge by name:
// override a default, disable it, or add a custom feed), and returns any warnings
// for enabled feeds that were skipped (unknown type or missing URL).
func ResolveVEXFeeds(cfg config.VEXFeedConfig, fetcher *vexfeed.HTTPFetcher) (overlay, correlation []vexfeed.FeedSource, warnings []string) {
	specs := builtinFeedSpecs(cfg)
	index := make(map[string]int, len(specs))
	for i, s := range specs {
		index[s.name] = i
	}
	for _, delta := range cfg.Feeds {
		name := strings.TrimSpace(delta.Name)
		if name == "" {
			warnings = append(warnings, "vexfeed.feeds entry with no name ignored")
			continue
		}
		if i, ok := index[name]; ok {
			specs[i] = applyFeedDelta(specs[i], delta)
		} else {
			specs = append(specs, specFromDelta(name, delta))
			index[name] = len(specs) - 1
		}
	}
	for _, s := range specs {
		if !s.enabled {
			continue
		}
		if strings.TrimSpace(s.url) == "" {
			warnings = append(warnings, fmt.Sprintf("feed %q has no URL; skipped", s.name))
			continue
		}
		src := buildFeedSource(s, fetcher)
		if src == nil {
			warnings = append(warnings, fmt.Sprintf("feed %q has unknown type %q; skipped", s.name, s.typ))
			continue
		}
		if s.class == feedClassOverlay {
			overlay = append(overlay, src)
		} else {
			correlation = append(correlation, src)
		}
	}
	return overlay, correlation, warnings
}

// builtinFeedSpecs derives the default feed set from the legacy URL fields so
// existing configs keep their behaviour. rhel_url remains a deprecated alias for
// rhel_csaf_url.
func builtinFeedSpecs(cfg config.VEXFeedConfig) []feedSpec {
	csafURL := cfg.RHELCSAFURL
	if csafURL == "" {
		csafURL = cfg.RHELURL
	}
	return []feedSpec{
		{name: "rhel-vex", typ: "csaf-dir", class: feedClassOverlay, url: cfg.RHELVEXURL, enabled: true},
		{name: "alpine", typ: "zip-osv", class: feedClassCorrelation, url: cfg.AlpineOSVURL, enabled: true},
		{name: "rocky", typ: "zip-osv", class: feedClassCorrelation, url: cfg.RockyOSVURL, enabled: true},
		{name: "wolfi", typ: "url", kind: "osv", class: feedClassCorrelation, url: cfg.WolfiOSVURL, enabled: true},
		{name: "rhel-csaf", typ: "csaf-dir", class: feedClassCorrelation, url: csafURL, enabled: true},
	}
}

// applyFeedDelta overrides a built-in spec with the non-empty fields of a delta
// (an unset `enabled` keeps the default's state).
func applyFeedDelta(base feedSpec, delta config.FeedConfig) feedSpec {
	if v := strings.TrimSpace(delta.Type); v != "" {
		base.typ = v
	}
	if v := normalizeFeedClass(delta.Class); v != "" {
		base.class = v
	}
	if v := strings.TrimSpace(delta.URL); v != "" {
		base.url = v
	}
	if v := strings.TrimSpace(delta.Kind); v != "" {
		base.kind = v
	}
	if delta.Enabled != nil {
		base.enabled = *delta.Enabled
	}
	return base
}

// specFromDelta builds a new feed spec for a name not present in the defaults. A
// custom feed defaults to the correlation class and is enabled unless disabled.
func specFromDelta(name string, delta config.FeedConfig) feedSpec {
	class := normalizeFeedClass(delta.Class)
	if class == "" {
		class = feedClassCorrelation
	}
	enabled := true
	if delta.Enabled != nil {
		enabled = *delta.Enabled
	}
	return feedSpec{
		name:    name,
		typ:     strings.TrimSpace(delta.Type),
		class:   class,
		url:     strings.TrimSpace(delta.URL),
		kind:    strings.TrimSpace(delta.Kind),
		enabled: enabled,
	}
}

func normalizeFeedClass(class string) string {
	switch strings.ToLower(strings.TrimSpace(class)) {
	case feedClassOverlay:
		return feedClassOverlay
	case feedClassCorrelation:
		return feedClassCorrelation
	default:
		return ""
	}
}

// buildFeedSource constructs the FeedSource for a spec's type, or nil for an unknown
// type. type=url defaults its parse kind to osv.
func buildFeedSource(s feedSpec, fetcher *vexfeed.HTTPFetcher) vexfeed.FeedSource {
	switch strings.ToLower(s.typ) {
	case "csaf-dir":
		return vexfeed.CSAFDirectoryFeedSource{Name_: s.name, URL: s.url, Fetcher: fetcher}
	case "zip-osv":
		return vexfeed.ZipOSVFeedSource{Name_: s.name, URL: s.url, Fetcher: fetcher}
	case "url":
		kind := s.kind
		if kind == "" {
			kind = "osv"
		}
		return vexfeed.URLFeedSource{Name_: s.name, URL: s.url, Kind: kind, Fetcher: fetcher}
	default:
		return nil
	}
}
