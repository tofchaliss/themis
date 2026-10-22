package serializer_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

func hook(kind string, snap map[string]string) app.Intent {
	s := map[string]string{app.SnapshotWebhookEvent: kind}
	for k, v := range snap {
		s[k] = v
	}
	return app.Intent{ID: "int-w", Type: app.IntentWebhook, Destination: "slack-sec", ReleaseID: "rel-1", FindingID: "fnd-1", Snapshot: s}
}

func renderHook(t *testing.T, r serializer.OutwardRenderer, in app.Intent) serializer.WebhookDocument {
	t.Helper()
	payload, err := r.RenderIntentPayload(context.Background(), in)
	if err != nil {
		t.Fatalf("render %s: %v", in.Snapshot[app.SnapshotWebhookEvent], err)
	}
	subject, body := app.SplitPayload(payload)
	var doc serializer.WebhookDocument
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	if subject != doc.Summary || !strings.HasPrefix(doc.Text, doc.Summary) {
		t.Fatalf("subject %q vs summary %q vs text %q", subject, doc.Summary, doc.Text)
	}
	return doc
}

// D4: each event kind renders the stable document — names from Registry, a summary a person can
// read in a channel, and the link into the dashboard.
func TestRenderWebhook_Kinds(t *testing.T) {
	r := serializer.NewOutwardRenderer(&postureSource{rows: estate()}).
		WithIdentity(identitySource{ref: domain.RollupProductRef{Product: "smallbox", Project: "demo", Version: "1.1.0", ReleaseID: "rel-1"}}).
		WithDashboardURL("https://themis.example/ ")
	doc := renderHook(t, r, hook(app.WebhookReleaseEvaluated, map[string]string{
		app.SnapshotOutcomeNew: "2", app.SnapshotOutcomeReappeared: "0", app.SnapshotOutcomeNoLongerPresent: "1"}))
	if doc.Event != "release_evaluated" || doc.Product != "smallbox" || doc.Release != "1.1.0" || doc.Link != "https://themis.example/#/release/rel-1" ||
		!strings.Contains(doc.Summary, "Critical 2, High 2") || !strings.Contains(doc.Summary, "1 no longer present (still open)") ||
		!strings.HasSuffix(doc.Text, doc.Link) {
		t.Fatalf("evaluated = %+v", doc)
	}
	cves := make([]string, 25)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-%02d", i)
	}
	cases := map[string]struct {
		snap map[string]string
		want []string
	}{
		app.WebhookRebuildExhausted: {map[string]string{app.SnapshotRebuildAttempt: "2", app.SnapshotRebuildMaxAttempts: "2", app.SnapshotRebuildOpen: strings.Join(cves, ",")},
			[]string{"gave up on smallbox / demo v1.1.0 after 2 of 2", "CVE-19", "(+5 more)", "A person decides"}},
		app.WebhookReviewDueSoon: {map[string]string{app.SnapshotCVE: "CVE-1", app.SnapshotStance: "accepted_risk", app.SnapshotReviewBy: "2026-11-05T00:00:00Z", app.SnapshotOwner: "jane"},
			[]string{"Review due 2026-11-05 for CVE-1 (accepted_risk)", "owner jane", "comes back to the queue"}},
		app.WebhookDispositionStale: {map[string]string{app.SnapshotCVE: "CVE-2", app.SnapshotReason: "the CVE entered KEV", app.SnapshotStance: "not_affected"},
			[]string{"CVE-2 on smallbox / demo v1.1.0 needs another look: the CVE entered KEV", "not_affected decision still stands"}},
		app.WebhookSLABreachDigest: {map[string]string{app.SnapshotDigestProduct: "Gateway", app.SnapshotDigestCount: "3", app.SnapshotDigestBuckets: "critical=1,high=2",
			app.SnapshotDigestCVEs: "CVE-1,CVE-2", app.SnapshotDigestReleases: "2"},
			[]string{"Gateway: 3 finding(s) passed their SLA deadline (critical=1, high=2): CVE-1, CVE-2 across 2 release(s)", "changes no decision"}},
	}
	for kind, tc := range cases {
		doc := renderHook(t, r, hook(kind, tc.snap))
		for _, w := range tc.want {
			if !strings.Contains(doc.Summary, w) {
				t.Errorf("%s summary lacks %q: %s", kind, w, doc.Summary)
			}
		}
	}
	// A digest for a product with no single release and no names.
	bare := serializer.NewOutwardRenderer(nil)
	in := hook(app.WebhookSLABreachDigest, nil)
	in.ReleaseID = ""
	d := renderHook(t, bare, in)
	if d.Link != "" || !strings.Contains(d.Summary, "a product: 0 finding(s)") || !strings.Contains(d.Summary, "see the dashboard") {
		t.Fatalf("bare digest = %+v", d)
	}
	// Fallbacks with no snapshot facts, no posture and no identity.
	d = renderHook(t, bare, hook(app.WebhookReviewDueSoon, nil))
	if !strings.Contains(d.Summary, "Review due soon for a finding (decision) on Release rel-1") || strings.Contains(d.Summary, "owner") {
		t.Fatalf("bare review = %+v", d)
	}
	d = renderHook(t, bare, hook(app.WebhookRebuildExhausted, nil))
	if !strings.Contains(d.Summary, "after ? of ? attempts; still open: see the ticket") {
		t.Fatalf("bare exhausted = %+v", d)
	}
	d = renderHook(t, bare, hook(app.WebhookReleaseEvaluated, nil))
	if d.Summary != "Themis evaluated Release rel-1." {
		t.Fatalf("bare evaluated = %+v", d)
	}
	d = renderHook(t, serializer.NewOutwardRenderer(&postureSource{err: errors.New("down")}).WithIdentity(identitySource{err: errors.New("down")}), hook(app.WebhookReleaseEvaluated, nil))
	if d.Product != "" || d.Summary != "Themis evaluated Release rel-1." {
		t.Fatalf("degraded evaluated = %+v", d)
	}
	d = renderHook(t, bare, hook(app.WebhookDispositionStale, map[string]string{app.SnapshotReviewBy: "x"}))
	if !strings.Contains(d.Summary, "A finding on Release rel-1 needs another look: its premise changed") {
		t.Fatalf("bare stale = %+v", d)
	}
}

func TestRenderWebhook_UnknownKind(t *testing.T) {
	if _, err := serializer.NewOutwardRenderer(nil).RenderIntentPayload(context.Background(), hook("bogus", nil)); err == nil {
		t.Fatal("unknown kind rendered")
	}
	in := hook("", nil)
	delete(in.Snapshot, app.SnapshotWebhookEvent)
	if _, err := serializer.NewOutwardRenderer(nil).RenderIntentPayload(context.Background(), in); err == nil {
		t.Fatal("missing kind rendered")
	}
}
