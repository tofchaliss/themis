package serializer_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

const frozenDecision = `{"decision_id":"dec-1","trigger_type":"fix_available",
	"policy":{"scope_kind":"product","version":3},
	"build_profile":{"scope":"project","revision":2,"sha256":"abc123"},
	"targeted":[{"finding_id":"f-1","cve":"CVE-2026-1","purl":"pkg:rpm/a","fixed_versions":["1.2"]}],
	"build":{"job":"image-build","params":{"base":"ubi9"}}}`

func rebuildIntent(snap map[string]string) app.Intent {
	s := map[string]string{
		app.SnapshotWebhookEvent: app.WebhookRebuildRequested, app.SnapshotRebuildDecision: frozenDecision,
		app.SnapshotRebuildCycleID: "7", app.SnapshotAttempt: "2", app.SnapshotRebuildTry: "3",
		app.SnapshotRebuildMaxAttempts: "2", app.SnapshotPriorSBOMID: "sbom-9",
	}
	for k, v := range snap {
		s[k] = v
	}
	return app.Intent{ID: "int-r", Type: app.IntentWebhook, Destination: "builders", ReleaseID: "rel-1", ProductID: "prod-1",
		ProjectID: "proj-1", Snapshot: s, CreatedAt: time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)}
}

// D6 and D36: the request is one CloudEvents document whose id is the intent id, built from the
// frozen decision and the cycle's numbers. Rendering it twice gives the same bytes.
func TestRenderRebuildRequested(t *testing.T) {
	r := serializer.NewOutwardRenderer(nil).WithIdentity(namedRelease)
	payload, err := r.RenderIntentPayload(context.Background(), rebuildIntent(nil))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	again, _ := r.RenderIntentPayload(context.Background(), rebuildIntent(nil))
	if string(payload) != string(again) {
		t.Fatal("the same intent must render the same bytes")
	}
	subject, body := app.SplitPayload(payload)
	if !strings.Contains(subject, "attempt 2, try 3") {
		t.Errorf("subject = %q", subject)
	}
	var ev serializer.RebuildRequestedEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	d := ev.Data
	if ev.SpecVersion != "1.0" || ev.Type != serializer.RebuildRequestedType || ev.ID != "int-r" || ev.Source != serializer.RebuildRequestedSource ||
		ev.Time != "2026-11-28T10:00:00Z" {
		t.Errorf("envelope = %+v", ev)
	}
	if d.ReleaseID != "rel-1" || d.ProductID != "prod-1" || d.ProjectID != "proj-1" || d.PriorSBOMID != "sbom-9" || d.DecisionID != "dec-1" ||
		d.CycleID != "7" || d.Attempt != 2 || d.Try != 3 || d.MaxAttempts != 2 || d.Reason != "fix_available" ||
		d.PolicyVersion != 3 || d.PolicyScope != "product" || d.BuildProfileRevision != 2 || d.BuildProfileScope != "project" ||
		d.BuildProfileSHA256 != "abc123" || d.ProductName == "" || d.ProjectName == "" || d.ReleaseVersion == "" {
		t.Errorf("data = %+v", d)
	}
	if !strings.Contains(string(d.Targeted), `"fixed_versions":["1.2"]`) || !strings.Contains(string(d.Build), `"job":"image-build"`) {
		t.Errorf("targeted and build must be passed on as recorded: %s / %s", d.Targeted, d.Build)
	}
}

// Without the name chain the ids stand; without a build profile its three fields are absent; bad
// numbers fall back. A decision that cannot be read, or names nothing, is refused.
func TestRenderRebuildRequested_FallbacksAndRefusals(t *testing.T) {
	r := serializer.NewOutwardRenderer(nil)
	bare := `{"decision_id":"dec-1","trigger_type":"new_sbom","policy":{},"targeted":[{"cve":"CVE-2026-1"}]}`
	_, body, err := r.RenderRebuildRequested(context.Background(), rebuildIntent(map[string]string{
		app.SnapshotRebuildDecision: bare, app.SnapshotAttempt: "x", app.SnapshotRebuildTry: "", app.SnapshotRebuildMaxAttempts: "?"}))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var ev serializer.RebuildRequestedEvent
	_ = json.Unmarshal(body, &ev)
	if ev.Data.Attempt != 1 || ev.Data.Try != 1 || ev.Data.MaxAttempts != 0 || ev.Data.ProductName != "" || ev.Data.BuildProfileSHA256 != "" ||
		strings.Contains(string(body), "build_profile_scope") || strings.Contains(string(body), `"build"`) {
		t.Errorf("bare = %s", body)
	}
	for name, decision := range map[string]string{
		"not json": `{`, "no decision id": `{"targeted":[{"cve":"CVE-2026-1"}]}`, "nothing targeted": `{"decision_id":"dec-1"}`,
	} {
		if _, err := r.RenderIntentPayload(context.Background(), rebuildIntent(map[string]string{app.SnapshotRebuildDecision: decision})); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestRenderRebuildNoticeEmail(t *testing.T) {
	r := serializer.NewOutwardRenderer(nil).WithIdentity(namedRelease)
	for kind, want := range map[string][2]string{
		app.NoticeRefused:      {"refused", "A refusal is not an attempt"},
		app.NoticeCycleRefused: {"stopped after refusals", "refused the rebuild request 3 times"},
		app.NoticeUncertain:    {"uncertain", "submitted, or not_submitted"},
	} {
		in := app.Intent{ID: "int-n", Type: app.IntentEmail, ReleaseID: "rel-1", Snapshot: map[string]string{
			"notification": "rebuild_notice", app.SnapshotRebuildNotice: kind, app.SnapshotRebuildIntentID: "int-r",
			app.SnapshotRebuildCycleID: "7", app.SnapshotRebuildAttempt: "1", app.SnapshotRebuildTry: "2",
			app.SnapshotRebuildChannel: "webhook", app.SnapshotRebuildNoticeText: "freeze window"}}
		if !in.IsRebuildNotification() {
			t.Fatal("the intent must read as a rebuild notice")
		}
		payload, err := r.RenderIntentPayload(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		subject, body := app.SplitPayload(payload)
		text := string(body)
		if !strings.Contains(subject, want[0]) || !strings.Contains(text, want[1]) || !strings.Contains(text, "No Finding was changed") ||
			!strings.Contains(text, "int-r") || !strings.Contains(text, "freeze window") || strings.Contains(text, "Build:") {
			t.Errorf("%s: subject %q\n%s", kind, subject, text)
		}
	}
}

func TestRenderWebhook_RebuildRecommended(t *testing.T) {
	r := serializer.NewOutwardRenderer(nil).WithIdentity(namedRelease)
	for reason, want := range map[string]string{
		"mode_ask": "a person decides", "no_build_profile": "No build profile applies", "": "A person decides",
	} {
		doc := renderHook(t, r, hook(app.WebhookRebuildRecommended, map[string]string{
			app.SnapshotRebuildRecommendReason: reason, app.SnapshotRebuildTargetedCount: "4", app.SnapshotTargetedCVEs: "CVE-2026-1,CVE-2026-2"}))
		if !strings.Contains(doc.Summary, "recommends a rebuild") || !strings.Contains(doc.Summary, "4 component(s)") ||
			!strings.Contains(doc.Summary, "CVE-2026-1, CVE-2026-2") || !strings.Contains(doc.Summary, want) || !strings.Contains(doc.Summary, "Nothing was started") {
			t.Errorf("%q: %s", reason, doc.Summary)
		}
	}
}

var namedRelease = identitySource{ref: domain.RollupProductRef{Product: "example-product", Project: "project-a", Version: "1.2.0"}}
