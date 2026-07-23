package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

func TestTier_StaleThresholdAndValid(t *testing.T) {
	cases := []struct {
		tier      domain.Tier
		threshold time.Duration
		valid     bool
	}{
		{domain.Tier1Critical, 25 * time.Hour, true},
		{domain.Tier2Recommended, 48 * time.Hour, true},
		{domain.Tier3Enrichment, 0, true},
		{domain.Tier4Advanced, 0, true},
		{domain.TierUnknown, 0, false},
		{domain.Tier(9), 0, false},
	}
	for _, c := range cases {
		if got := c.tier.StaleThreshold(); got != c.threshold {
			t.Errorf("tier %d threshold = %v, want %v", c.tier, got, c.threshold)
		}
		if got := c.tier.Valid(); got != c.valid {
			t.Errorf("tier %d valid = %v, want %v", c.tier, got, c.valid)
		}
	}
}

func TestFeedObservation_Evaluate(t *testing.T) {
	h := 26 * time.Hour // past the Tier-1 threshold, within Tier-2
	cases := []struct {
		name string
		obs  domain.FeedObservation
		want domain.FeedStatus
	}{
		{"tier1 healthy", domain.FeedObservation{Tier: domain.Tier1Critical, SinceLastSuccess: time.Hour}, domain.FeedHealthy},
		{"tier1 failing → stale", domain.FeedObservation{Tier: domain.Tier1Critical, ConsecutiveFailures: 1}, domain.FeedStale},
		{"tier1 overdue → stale", domain.FeedObservation{Tier: domain.Tier1Critical, SinceLastSuccess: h}, domain.FeedStale},
		{"tier2 failing → degraded", domain.FeedObservation{Tier: domain.Tier2Recommended, ConsecutiveFailures: 2}, domain.FeedDegraded},
		{"tier2 within thresh → healthy", domain.FeedObservation{Tier: domain.Tier2Recommended, SinceLastSuccess: h}, domain.FeedHealthy},
		{"tier2 overdue → degraded", domain.FeedObservation{Tier: domain.Tier2Recommended, SinceLastSuccess: 49 * time.Hour}, domain.FeedDegraded},
		{"tier3 failing → informational", domain.FeedObservation{Tier: domain.Tier3Enrichment, ConsecutiveFailures: 1}, domain.FeedInformational},
		{"unknown failing → informational", domain.FeedObservation{Tier: domain.TierUnknown, ConsecutiveFailures: 1}, domain.FeedInformational},
	}
	for _, c := range cases {
		if got := c.obs.Evaluate(); got != c.want {
			t.Errorf("%s: Evaluate = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFeedStatus_SetsSignalsStale(t *testing.T) {
	if !domain.FeedStale.SetsSignalsStale() {
		t.Error("Tier-1 stale must set signals_stale")
	}
	for _, s := range []domain.FeedStatus{domain.FeedHealthy, domain.FeedDegraded, domain.FeedInformational} {
		if s.SetsSignalsStale() {
			t.Errorf("%q must not set signals_stale", s)
		}
	}
}
