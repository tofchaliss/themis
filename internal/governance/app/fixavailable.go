package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The fix-available path (EDR-INCIDENT-01 D1). Knowledge emits knowledge.fix_published.v1 per
// occurrence when a re-judgement finds an OPEN row behind a bound the previous judgement did not
// know. Governance records each as a NOTICE inside the inbox transaction (cheap, idempotent) and
// a sweep groups the unannounced notices per release and publishes ONE
// governance.fix_available.v1 for each — so a wave that lands two hundred bounds on a release
// in one sweep is one message, not two hundred. Nothing here decides: no Finding, Position or
// proposal changes.

// EventFixAvailable announces that a vendor fix is newly on record for things one release has
// open. A fact, never a transition.
const EventFixAvailable = "governance.fix_available"

// DefaultFixAvailableInterval is the sweep cadence (THEMIS_FIX_AVAILABLE_INTERVAL): it is also
// the window notices for one release are gathered over before they go out as one message.
const DefaultFixAvailableInterval = 10 * time.Minute

// FixAvailableSweepBatch bounds the notices one sweep reads; a backlog drains over ticks.
const FixAvailableSweepBatch = 2000

// FixNotice is one recorded "fix published" fact: this release's occurrence of this package is
// behind this bound. The key is (release, faultline, purl, fix): a re-delivery or a restatement
// records nothing new.
type FixNotice struct {
	ReleaseID   string
	FaultlineID string
	CVE         string
	PURL        string
	Package     string
	Ecosystem   string
	Fix         string
	Advisories  []string
	LearnedAt   time.Time
	// FindingID is filled by the store when it lists pending notices (the Finding of
	// (release, faultline), when one exists); empty on record.
	FindingID domain.FindingID
}

// FixNoticeStore is the notice persistence seam.
type FixNoticeStore interface {
	// RecordFixNotices stores the notices, ignoring any already recorded.
	RecordFixNotices(ctx context.Context, notices []FixNotice) error
	// PendingFixNotices lists unannounced notices, oldest release first, bounded. A notice
	// whose Finding rests on a not_affected Position is not pending: a fix for a flaw the
	// release does not have is not news. (An accepted risk IS told — the acceptance may have
	// rested on there being no fix.)
	PendingFixNotices(ctx context.Context, limit int) ([]FixNotice, error)
	// MarkFixNoticesAnnounced marks the release's listed notices announced and writes the
	// announcement's outbox note in one transaction.
	MarkFixNoticesAnnounced(ctx context.Context, releaseID string, notices []FixNotice, note OutboxNote) error
}

// InboundFixPublished is the decoded knowledge.fix_published.v1.
type InboundFixPublished struct {
	FaultlineID string
	CVE         string
	ReleaseID   string
	PURL        string
	Package     string
	Ecosystem   string
	Fixes       []string
	Advisories  []string
	OccurredAt  time.Time
}

// WithFixNotices wires the notice store the fix-published fact is recorded in.
func (c *Coordinator) WithFixNotices(s FixNoticeStore) *Coordinator {
	c.fixes = s
	return c
}

// OnFixPublished records the fact as notices, one per new bound (D1). A Coordinator without a
// notice store ignores it; an event naming no release, no package or no bound records nothing
// (an announcement with no subject is not one), and is not an error — nothing to retry.
func (c *Coordinator) OnFixPublished(ctx context.Context, in InboundFixPublished) error {
	if c.fixes == nil {
		return nil
	}
	if strings.TrimSpace(in.ReleaseID) == "" || strings.TrimSpace(in.FaultlineID) == "" || strings.TrimSpace(in.Package) == "" {
		return nil
	}
	var notices []FixNotice
	for _, fix := range in.Fixes {
		if strings.TrimSpace(fix) == "" {
			continue
		}
		notices = append(notices, FixNotice{
			ReleaseID: in.ReleaseID, FaultlineID: in.FaultlineID, CVE: in.CVE, PURL: in.PURL,
			Package: in.Package, Ecosystem: in.Ecosystem, Fix: fix, Advisories: in.Advisories,
			LearnedAt: in.OccurredAt.UTC(),
		})
	}
	if len(notices) == 0 {
		return nil
	}
	return c.fixes.RecordFixNotices(ctx, notices)
}

// FixAvailableSweep turns pending notices into one announcement per release.
type FixAvailableSweep struct {
	store FixNoticeStore
	clock Clock
}

// NewFixAvailableSweep wires the sweep.
func NewFixAvailableSweep(store FixNoticeStore, clock Clock) *FixAvailableSweep {
	return &FixAvailableSweep{store: store, clock: clock}
}

// Run performs one pass and reports how many releases were announced. The items of one
// announcement merge the release's notices per (Finding, package): the bounds and advisories
// of one package are one line. A store fault is fatal to the pass; the notices it did not
// reach stay pending.
func (s *FixAvailableSweep) Run(ctx context.Context) (announced int, err error) {
	pending, err := s.store.PendingFixNotices(ctx, FixAvailableSweepBatch)
	if err != nil {
		return 0, fmt.Errorf("list pending fix notices: %w", err)
	}
	byRelease := map[string][]FixNotice{}
	var order []string
	for _, n := range pending {
		if _, seen := byRelease[n.ReleaseID]; !seen {
			order = append(order, n.ReleaseID)
		}
		byRelease[n.ReleaseID] = append(byRelease[n.ReleaseID], n)
	}
	now := s.clock.Now()
	for _, rel := range order {
		if err := ctx.Err(); err != nil {
			return announced, err
		}
		notices := byRelease[rel]
		ev := domain.NewFixAvailable(rel, mergeNotices(notices), now)
		if err := s.store.MarkFixNoticesAnnounced(ctx, rel, notices,
			OutboxNote{EventType: EventFixAvailable, Event: ev, OccurredAt: now}); err != nil {
			return announced, fmt.Errorf("announce fixes for %s: %w", rel, err)
		}
		announced++
	}
	return announced, nil
}

// mergeNotices folds a release's notices into items, one per (Finding, package), in notice order.
func mergeNotices(notices []FixNotice) []domain.FixAvailableItem {
	type key struct{ finding, cve, pkg string }
	at := map[key]int{}
	var items []domain.FixAvailableItem
	for _, n := range notices {
		k := key{string(n.FindingID), n.CVE, n.Package}
		i, ok := at[k]
		if !ok {
			i = len(items)
			at[k] = i
			items = append(items, domain.FixAvailableItem{FindingID: n.FindingID, CVE: n.CVE, Package: n.Package, Ecosystem: n.Ecosystem})
		}
		items[i].Fixes = appendUnique(items[i].Fixes, n.Fix)
		for _, a := range n.Advisories {
			items[i].Advisories = appendUnique(items[i].Advisories, a)
		}
	}
	return items
}

func appendUnique(list []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// RunEvery runs the sweep on a cadence until ctx is cancelled, reporting each pass through
// report (nil = silent).
func (s *FixAvailableSweep) RunEvery(ctx context.Context, every time.Duration, report func(announced int, err error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := s.Run(ctx)
			if report != nil {
				report(n, err)
			}
		}
	}
}
