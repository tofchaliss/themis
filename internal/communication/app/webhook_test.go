package app_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

func routed(store *intentStore) *app.DeliveryIntentService {
	return intentSvc(store, app.DeliveryIntentConfig{WebhookRoutes: map[string]string{
		app.WebhookReleaseEvaluated: "slack-sec", app.WebhookSLABreachDigest: " teams ",
	}})
}

func TestEnqueueWebhook(t *testing.T) {
	ctx := context.Background()
	store := newIntentStore()
	svc := routed(store)
	if a, ok := svc.WebhookAudience(app.WebhookSLABreachDigest); !ok || a != "teams" {
		t.Fatalf("audience = %q %v", a, ok)
	}
	// Unrouted: nothing recorded, no error.
	if _, ok, err := svc.EnqueueWebhook(ctx, lineage(), "env-1", app.WebhookReviewDueSoon, "rel-1", "", "", "", nil); ok || err != nil || len(store.created) != 0 {
		t.Fatalf("unrouted = %v %v", ok, err)
	}
	// Routed with no subject: fails closed.
	if _, _, err := svc.EnqueueWebhook(ctx, lineage(), "env-1", app.WebhookReleaseEvaluated, " ", "", "", "", nil); !errors.Is(err, app.ErrNoSubject) {
		t.Fatalf("no subject = %v", err)
	}
	in, ok, err := svc.EnqueueWebhook(ctx, lineage(), "env-1", app.WebhookReleaseEvaluated, "rel-1", "prod-1", "prj-1", "fnd-1", map[string]string{"x": "y"})
	if err != nil || !ok || in.Type != app.IntentWebhook || in.Destination != "slack-sec" || in.Snapshot[app.SnapshotWebhookEvent] != app.WebhookReleaseEvaluated ||
		in.Snapshot["release_id"] != "rel-1" || in.Snapshot["finding_id"] != "fnd-1" || in.Snapshot["x"] != "y" || in.ProductID != "prod-1" {
		t.Fatalf("routed = %+v %v %v", in, ok, err)
	}
}

type fakeDigestStore struct {
	rows     []app.SLABreachRecord
	marked   map[string]string
	recErr   error
	listErr  error
	markErr  error
	recorded int
}

func (f *fakeDigestStore) RecordSLABreach(_ context.Context, r app.SLABreachRecord) error {
	if f.recErr != nil {
		return f.recErr
	}
	f.recorded++
	f.rows = append(f.rows, r)
	return nil
}

func (f *fakeDigestStore) PendingSLABreaches(context.Context) ([]app.SLABreachRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []app.SLABreachRecord
	for _, r := range f.rows {
		if _, done := f.marked[r.FindingID]; !done {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeDigestStore) MarkSLABreachesDigested(_ context.Context, keys []app.SLABreachRecord, id string) error {
	if f.markErr != nil {
		return f.markErr
	}
	if f.marked == nil {
		f.marked = map[string]string{}
	}
	for _, k := range keys {
		f.marked[k.FindingID] = id
	}
	return nil
}

type byRelease map[string]domain.RollupProductRef

func (b byRelease) ReleaseIdentity(_ context.Context, id string) (domain.RollupProductRef, error) {
	if r, ok := b[id]; ok {
		return r, nil
	}
	return domain.RollupProductRef{}, errors.New("unknown")
}

func breach(f, rel, cve, bucket string) app.SLABreachRecord {
	return app.SLABreachRecord{FindingID: f, ReleaseID: rel, CVE: cve, Bucket: bucket, PeriodStart: intentEpoch, Due: intentEpoch}
}

// D4: one digest per Product per pass — two releases of one product are one message — and a
// release whose product cannot be named is still sent, under its own id.
func TestSLADigest_OnePerProduct(t *testing.T) {
	ctx := context.Background()
	store := newIntentStore()
	ds := &fakeDigestStore{}
	ids := byRelease{"rel-1": {Product: "Gateway"}, "rel-2": {Product: "Gateway"}, "rel-3": {Product: "Portal"}}
	d := app.NewSLADigest(ds, routed(store), ids, &intentIDs{}, intentClock{})
	for _, r := range []app.SLABreachRecord{breach("f1", "rel-1", "CVE-2", "critical"), breach("f2", "rel-2", "CVE-1", "high"),
		breach("f3", "rel-2", "CVE-1", "high"), breach("f4", "rel-3", "CVE-9", ""), breach("f5", "rel-x", "", "low")} {
		if err := d.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if ds.rows[0].RecordedAt.IsZero() {
		t.Fatal("recorded_at not stamped")
	}
	n, err := d.Run(ctx)
	if err != nil || n != 3 || len(store.created) != 3 {
		t.Fatalf("run = %d %v, %d intents", n, err, len(store.created))
	}
	byProduct := map[string]app.Intent{}
	for _, in := range store.created {
		byProduct[in.Snapshot[app.SnapshotDigestProduct]] = in
	}
	g := byProduct["Gateway"]
	if g.Snapshot[app.SnapshotDigestCount] != "3" || g.Snapshot[app.SnapshotDigestCVEs] != "CVE-1,CVE-2" ||
		g.Snapshot[app.SnapshotDigestBuckets] != "critical=1,high=2" || g.Snapshot[app.SnapshotDigestReleases] != "2" ||
		g.ReleaseID != "" || g.Destination != "teams" || !strings.HasPrefix(g.OriginEventID, "sla-digest:") {
		t.Fatalf("gateway = %+v", g)
	}
	if p := byProduct["Portal"]; p.ReleaseID != "rel-3" || p.Snapshot[app.SnapshotDigestBuckets] != "unknown=1" {
		t.Fatalf("portal = %+v", p)
	}
	if _, ok := byProduct["Release rel-x"]; !ok {
		t.Fatalf("unresolved product not sent: %v", byProduct)
	}
	if n, _ := d.Run(ctx); n != 0 {
		t.Fatalf("second run sent %d", n)
	}
}

func TestSLADigest_RecordRules(t *testing.T) {
	ctx := context.Background()
	ds := &fakeDigestStore{}
	unrouted := app.NewSLADigest(ds, intentSvc(newIntentStore(), app.DeliveryIntentConfig{}), nil, &intentIDs{}, intentClock{})
	if err := unrouted.Record(ctx, breach("f1", "rel-1", "CVE-1", "high")); err != nil || ds.recorded != 0 {
		t.Fatalf("unrouted stored %d (%v)", ds.recorded, err)
	}
	d := app.NewSLADigest(ds, routed(newIntentStore()), nil, &intentIDs{}, intentClock{})
	if err := d.Record(ctx, breach("", "rel-1", "CVE-1", "high")); err != nil || ds.recorded != 0 {
		t.Fatalf("no subject stored %d", ds.recorded)
	}
	ds.recErr = errors.New("db")
	if err := d.Record(ctx, breach("f1", "rel-1", "CVE-1", "high")); err == nil {
		t.Fatal("record error swallowed")
	}
}

func TestSLADigest_Failures(t *testing.T) {
	ctx := context.Background()
	if _, err := app.NewSLADigest(&fakeDigestStore{listErr: errors.New("db")}, routed(newIntentStore()), nil, &intentIDs{}, intentClock{}).Run(ctx); err == nil {
		t.Fatal("list error swallowed")
	}
	ds := &fakeDigestStore{rows: []app.SLABreachRecord{breach("f1", "rel-1", "CVE-1", "high")}, markErr: errors.New("db")}
	if _, err := app.NewSLADigest(ds, routed(newIntentStore()), nil, &intentIDs{}, intentClock{}).Run(ctx); err == nil {
		t.Fatal("mark error swallowed")
	}
	failing := newIntentStore()
	failing.err = errors.New("db")
	ds = &fakeDigestStore{rows: []app.SLABreachRecord{breach("f1", "rel-1", "CVE-1", "high")}}
	if _, err := app.NewSLADigest(ds, routed(failing), nil, &intentIDs{}, intentClock{}).Run(ctx); err == nil {
		t.Fatal("enqueue error swallowed")
	}
}

// The CVE list is capped; the count is complete.
func TestSLADigest_CVEListCapped(t *testing.T) {
	ctx := context.Background()
	store := newIntentStore()
	ds := &fakeDigestStore{}
	for i := 0; i < app.SLADigestCVELimit+7; i++ {
		ds.rows = append(ds.rows, breach(fmt.Sprintf("f%03d", i), "rel-1", fmt.Sprintf("CVE-%03d", i), "medium"))
	}
	if _, err := app.NewSLADigest(ds, routed(store), nil, &intentIDs{}, intentClock{}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	s := store.created[0].Snapshot
	if s[app.SnapshotDigestCount] != fmt.Sprint(app.SLADigestCVELimit+7) || len(strings.Split(s[app.SnapshotDigestCVEs], ",")) != app.SLADigestCVELimit {
		t.Fatalf("cap = %s / %d", s[app.SnapshotDigestCount], len(strings.Split(s[app.SnapshotDigestCVEs], ",")))
	}
}

func TestSLADigest_RunEvery(t *testing.T) {
	ds := &fakeDigestStore{rows: []app.SLABreachRecord{breach("f1", "rel-1", "CVE-1", "high")}}
	d := app.NewSLADigest(ds, routed(newIntentStore()), nil, &intentIDs{}, intentClock{})
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan int, 1)
	go d.RunEvery(ctx, time.Millisecond, func(n int, err error) {
		if n > 0 {
			select {
			case got <- n:
			default:
			}
			cancel()
		}
	})
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("digest never reported")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel2()
	d.RunEvery(ctx2, time.Millisecond, nil)
}

type tagReader struct {
	tags []string
	err  error
}

func (r tagReader) ReleaseTags(context.Context, string) ([]string, error) { return r.tags, r.err }

// D7: a "kind#tag" route sends a tagged Release's event to its own audience, before the plain
// route; a release without the tag, or a tag read failure, falls back to the plain route.
func TestEnqueueWebhook_TagRouting(t *testing.T) {
	ctx := context.Background()
	cfg := app.DeliveryIntentConfig{WebhookRoutes: map[string]string{
		app.WebhookReleaseEvaluated:                    "slack-sec",
		app.WebhookReleaseEvaluated + "#team:payments": "slack-payments",
		app.WebhookReleaseEvaluated + "#a-first":       "slack-a",
		app.WebhookReviewDueSoon + "#team:payments":    "slack-payments",
	}}
	store := newIntentStore()
	svc := intentSvc(store, cfg).WithReleaseTags(tagReader{tags: []string{"team:payments", "env:prod"}})
	in, ok, err := svc.EnqueueWebhook(ctx, lineage(), "env-1", app.WebhookReleaseEvaluated, "rel-1", "", "", "", nil)
	if err != nil || !ok || in.Destination != "slack-payments" || in.Snapshot[app.SnapshotWebhookRoutedByTag] != "team:payments" {
		t.Fatalf("tagged = %+v %v %v", in, ok, err)
	}
	// Only a tag route exists for review_due_soon: a tagged release posts, an untagged one does not.
	if in, ok, _ := svc.EnqueueWebhook(ctx, lineage(), "env-2", app.WebhookReviewDueSoon, "rel-1", "", "", "f", nil); !ok || in.Destination != "slack-payments" {
		t.Fatalf("tag-only route = %+v %v", in, ok)
	}
	untagged := intentSvc(newIntentStore(), cfg).WithReleaseTags(tagReader{tags: []string{"env:prod"}})
	if in, _, _ := untagged.EnqueueWebhook(ctx, lineage(), "env-3", app.WebhookReleaseEvaluated, "rel-2", "", "", "", nil); in.Destination != "slack-sec" || in.Snapshot[app.SnapshotWebhookRoutedByTag] != "" {
		t.Fatalf("untagged = %+v", in)
	}
	if _, ok, _ := untagged.EnqueueWebhook(ctx, lineage(), "env-4", app.WebhookReviewDueSoon, "rel-2", "", "", "f", nil); ok {
		t.Fatal("untagged release posted on a tag-only route")
	}
	failing := intentSvc(newIntentStore(), cfg).WithReleaseTags(tagReader{err: errors.New("registry down")})
	if in, _, _ := failing.EnqueueWebhook(ctx, lineage(), "env-5", app.WebhookReleaseEvaluated, "rel-1", "", "", "", nil); in.Destination != "slack-sec" {
		t.Fatalf("tag read failure = %+v", in)
	}
	// A kind with no tag routes never reads tags.
	plainOnly := intentSvc(newIntentStore(), app.DeliveryIntentConfig{WebhookRoutes: map[string]string{app.WebhookDispositionStale: "slack-sec"}}).
		WithReleaseTags(tagReader{err: errors.New("must not be called")})
	if in, ok, _ := plainOnly.EnqueueWebhook(ctx, lineage(), "env-7", app.WebhookDispositionStale, "rel-1", "", "", "f", nil); !ok || in.Destination != "slack-sec" {
		t.Fatalf("plain only = %+v %v", in, ok)
	}
	// Sorted tags decide between two matching tag routes.
	both := intentSvc(newIntentStore(), cfg).WithReleaseTags(tagReader{tags: []string{"team:payments", "a-first"}})
	if in, _, _ := both.EnqueueWebhook(ctx, lineage(), "env-6", app.WebhookReleaseEvaluated, "rel-1", "", "", "", nil); in.Destination != "slack-a" {
		t.Fatalf("two matches = %+v", in)
	}
}
