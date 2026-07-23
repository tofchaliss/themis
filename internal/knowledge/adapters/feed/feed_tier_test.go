package feed_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

func TestRegistry_Tier(t *testing.T) {
	r := feed.NewRegistry()
	cases := map[string]domain.Tier{
		"nvd":       domain.Tier1Critical,
		"epsskev":   domain.Tier1Critical,
		"osv":       domain.Tier2Recommended,
		"redhat":    domain.Tier2Recommended,
		"exploitdb": domain.Tier2Recommended,
		"vexfeed":   domain.Tier3Enrichment,
		"bogus":     domain.TierUnknown,
	}
	for source, want := range cases {
		if got := r.Tier(source); got != want {
			t.Errorf("Tier(%q) = %d, want %d", source, got, want)
		}
	}
}

// Every registered feed source must carry a tier classification (no silent gaps).
func TestRegistry_AllSourcesClassified(t *testing.T) {
	r := feed.NewRegistry()
	for _, source := range r.Sources() {
		if r.Tier(source) == domain.TierUnknown {
			t.Errorf("feed source %q has no tier classification", source)
		}
	}
}
