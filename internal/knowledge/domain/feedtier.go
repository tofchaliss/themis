package domain

import "time"

// Tier is a feed source's authority/criticality tier (openspec/intel-source-tiers.md). It
// is a pure policy value: it decides how a feed's failure is surfaced — a Tier-1 failure
// marks signals stale and escalates, a Tier-2 failure only degrades, a Tier-3 failure is
// informational. This is the go-forward realization of D-FEED-2, where the taxonomy was
// documented but never applied in code (the v0.3.x feed_health treated every feed alike).
// The domain owns the tier *policy*; which feed is which tier is adapter classification.
type Tier int

const (
	// TierUnknown is an unclassified feed (treated informationally — never escalates).
	TierUnknown Tier = 0
	// Tier1Critical — mandatory sources (NVD, EPSS, KEV, scanner evidence). Failure past
	// threshold makes findings/risk unreliable → signals stale + escalate.
	Tier1Critical Tier = 1
	// Tier2Recommended — reduced ecosystem coverage without them (OSV, Red Hat CSAF,
	// ExploitDB, distro). Failure degrades but never blocks.
	Tier2Recommended Tier = 2
	// Tier3Enrichment — AI-enrichment gold (VEX, analyst decisions, metadata). Missing
	// data lowers enrichment quality but has no signal-pipeline impact.
	Tier3Enrichment Tier = 3
	// Tier4Advanced — future / paid sources; informational until an adapter ships.
	Tier4Advanced Tier = 4
)

// Valid reports whether t is a recognized tier.
func (t Tier) Valid() bool { return t >= Tier1Critical && t <= Tier4Advanced }

// StaleThreshold is how long a feed of this tier may go without a successful sync before it
// counts as stale. Zero means staleness does not apply (Tier 3/4 carry no signal, so their
// age never marks the platform stale).
func (t Tier) StaleThreshold() time.Duration {
	switch t {
	case Tier1Critical:
		return 25 * time.Hour
	case Tier2Recommended:
		return 48 * time.Hour
	default:
		return 0
	}
}

// FeedStatus is the tier-differentiated health verdict for a feed.
type FeedStatus string

const (
	// FeedHealthy — syncing within threshold with no active failure streak.
	FeedHealthy FeedStatus = "healthy"
	// FeedStale — a Tier-1 feed failing/overdue: flips signals_stale and escalates.
	FeedStale FeedStatus = "stale"
	// FeedDegraded — a Tier-2 feed failing: a degraded_feeds entry, no stale flag.
	FeedDegraded FeedStatus = "degraded"
	// FeedInformational — a Tier-3/4 (or unknown) feed failing: logged, no status impact.
	FeedInformational FeedStatus = "informational"
)

// SetsSignalsStale reports whether this verdict must flip the status API's signals_stale
// flag — Tier-1 escalation only, the behaviour the v0.3.x taxonomy never wired.
func (s FeedStatus) SetsSignalsStale() bool { return s == FeedStale }

// FeedObservation is what a feed-health store records per feed: its tier, whether it is in
// an active failure streak, and how long since its last successful sync.
type FeedObservation struct {
	Tier                Tier
	ConsecutiveFailures int
	SinceLastSuccess    time.Duration
}

// Evaluate returns the tier-aware health verdict (the D-FEED-2 fix). A feed is unhealthy
// when it has an active failure streak OR has exceeded its tier's stale threshold; the
// *verdict* then follows the tier — Tier 1 → stale (escalate), Tier 2 → degraded, Tier 3/4
// → informational. A feed within threshold with no failures is always FeedHealthy,
// whatever its tier.
func (o FeedObservation) Evaluate() FeedStatus {
	threshold := o.Tier.StaleThreshold()
	overdue := threshold > 0 && o.SinceLastSuccess > threshold
	failing := o.ConsecutiveFailures > 0
	if !failing && !overdue {
		return FeedHealthy
	}
	switch o.Tier {
	case Tier1Critical:
		return FeedStale
	case Tier2Recommended:
		return FeedDegraded
	default:
		return FeedInformational
	}
}
