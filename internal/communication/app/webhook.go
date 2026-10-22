package app

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

// The webhook channel's two stores and the SLA digest (EDR-REMEDIATION-01 D4).

// Snapshot keys a webhook intent carries beyond the shared ones (written by the inbound
// consumer and the digest, read by the renderer).
const (
	SnapshotCVE            = "cve"
	SnapshotStance         = "stance"
	SnapshotReviewBy       = "review_by"
	SnapshotOwner          = "owner"
	SnapshotReason         = "reason"
	SnapshotDigestProduct  = "digest_product"
	SnapshotDigestCount    = "digest_count"
	SnapshotDigestBuckets  = "digest_buckets" // "critical=1,high=3"
	SnapshotDigestCVEs     = "digest_cves"    // comma-separated, sorted, capped
	SnapshotDigestReleases = "digest_releases"
)

// WebhookHealthStore records per-destination health.
type WebhookHealthStore interface {
	// WebhookHealth returns a destination's health; a destination never recorded is active.
	WebhookHealth(ctx context.Context, destination string) (domain.WebhookHealth, error)
	SaveWebhookHealth(ctx context.Context, h domain.WebhookHealth, at time.Time) error
	ListWebhookHealth(ctx context.Context) ([]domain.WebhookHealth, error)
}

// SLABreachRecord is one SLA breach waiting for its Product's digest.
type SLABreachRecord struct {
	FindingID   string
	PeriodStart time.Time
	ReleaseID   string
	CVE         string
	Bucket      string
	Due         time.Time
	RecordedAt  time.Time
}

// SLADigestStore holds breaches until the daily digest sends them.
type SLADigestStore interface {
	// RecordSLABreach stores one breach, once per (finding, period).
	RecordSLABreach(ctx context.Context, r SLABreachRecord) error
	PendingSLABreaches(ctx context.Context) ([]SLABreachRecord, error)
	MarkSLABreachesDigested(ctx context.Context, keys []SLABreachRecord, digestID string) error
}

// SLADigestCVELimit caps the CVE list a digest message carries; the count is complete.
const SLADigestCVELimit = 50

// SLADigest sends one webhook per Product per pass for the SLA breaches recorded since the last
// pass (D4: a daily digest, never one message per Finding). A breach changes no decision, and the
// message says so.
type SLADigest struct {
	store    SLADigestStore
	intents  *DeliveryIntentService
	identity ReleaseIdentityReader // may be nil: breaches then group under their release ids
	ids      IDGenerator
	clock    Clock
}

// NewSLADigest wires the digest.
func NewSLADigest(store SLADigestStore, intents *DeliveryIntentService, identity ReleaseIdentityReader, ids IDGenerator, clock Clock) *SLADigest {
	return &SLADigest{store: store, intents: intents, identity: identity, ids: ids, clock: clock}
}

// Record stores a breach for the next digest, when the sla_breached route is configured. An
// unrouted breach is not stored: nothing would ever send it.
func (d *SLADigest) Record(ctx context.Context, r SLABreachRecord) error {
	if _, ok := d.intents.WebhookAudience(WebhookSLABreachDigest); !ok {
		return nil
	}
	if strings.TrimSpace(r.FindingID) == "" || strings.TrimSpace(r.ReleaseID) == "" {
		return nil // no subject: not a transport failure, nothing to retry
	}
	if r.RecordedAt.IsZero() {
		r.RecordedAt = d.clock.Now()
	}
	return d.store.RecordSLABreach(ctx, r)
}

type digestGroup struct {
	product  string
	releases map[string]bool
	buckets  map[string]int
	cves     map[string]bool
	rows     []SLABreachRecord
}

// Run sends the pending breaches, one webhook per Product, and reports how many digests it
// enqueued. A Product whose name cannot be resolved is grouped by its release id, so a Registry
// outage still sends the breach rather than holding it.
func (d *SLADigest) Run(ctx context.Context) (int, error) {
	pending, err := d.store.PendingSLABreaches(ctx)
	if err != nil {
		return 0, fmt.Errorf("read pending SLA breaches: %w", err)
	}
	groups := map[string]*digestGroup{}
	names := map[string]string{}
	for _, r := range pending {
		name, ok := names[r.ReleaseID]
		if !ok {
			name = "Release " + r.ReleaseID
			if d.identity != nil {
				if ref, err := d.identity.ReleaseIdentity(ctx, r.ReleaseID); err == nil && ref.Product != "" {
					name = ref.Product
				}
			}
			names[r.ReleaseID] = name
		}
		g := groups[name]
		if g == nil {
			g = &digestGroup{product: name, releases: map[string]bool{}, buckets: map[string]int{}, cves: map[string]bool{}}
			groups[name] = g
		}
		g.releases[r.ReleaseID] = true
		g.buckets[firstNonBlank(r.Bucket, "unknown")]++
		if r.CVE != "" {
			g.cves[r.CVE] = true
		}
		g.rows = append(g.rows, r)
	}
	products := make([]string, 0, len(groups))
	for p := range groups {
		products = append(products, p)
	}
	sort.Strings(products)
	sent := 0
	for _, p := range products {
		g := groups[p]
		digestID := "sla-digest:" + d.ids.NewID()
		releases := sortedKeys(g.releases)
		snap := map[string]string{
			SnapshotDigestProduct:  g.product,
			SnapshotDigestCount:    strconv.Itoa(len(g.rows)),
			SnapshotDigestBuckets:  bucketLine(g.buckets),
			SnapshotDigestCVEs:     strings.Join(capList(sortedKeys(g.cves), SLADigestCVELimit), ","),
			SnapshotDigestReleases: strconv.Itoa(len(releases)),
		}
		subjectRelease := ""
		if len(releases) == 1 {
			subjectRelease = releases[0]
		}
		if _, _, err := d.intents.EnqueueWebhook(ctx, IntentLineage{EventType: "governance.sla_breached", EventID: digestID},
			digestID, WebhookSLABreachDigest, subjectRelease, g.product, "", "", snap); err != nil {
			return sent, fmt.Errorf("enqueue SLA digest for %s: %w", g.product, err)
		}
		if err := d.store.MarkSLABreachesDigested(ctx, g.rows, digestID); err != nil {
			return sent, fmt.Errorf("mark SLA digest for %s: %w", g.product, err)
		}
		sent++
	}
	return sent, nil
}

// RunEvery runs the digest on a cadence until ctx is cancelled.
func (d *SLADigest) RunEvery(ctx context.Context, every time.Duration, report func(sent int, err error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := d.Run(ctx)
			if report != nil {
				report(n, err)
			}
		}
	}
}

var bucketOrder = []string{"critical", "high", "medium", "low", "unknown"}

func bucketLine(b map[string]int) string {
	var parts []string
	for _, k := range bucketOrder {
		if b[k] > 0 {
			parts = append(parts, k+"="+strconv.Itoa(b[k]))
		}
	}
	return strings.Join(parts, ",")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func capList(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func firstNonBlank(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
