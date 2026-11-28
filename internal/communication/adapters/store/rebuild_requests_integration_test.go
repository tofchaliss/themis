//go:build integration

package store_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
)

// EDR-REBUILD-01 step R3 against real Postgres: a decision cycle round-trips with its frozen
// decision; requests are unique per cycle, attempt and try; a delivered intent moves its request
// in the same statement (webhook -> delivered, the built-in sender -> submitted); the hold and
// the last SBOM are one row per Release.
func TestRebuildRequestsStore(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	decision := []byte(`{"decision_id":"dec-1","z":1,"a":2}`)
	cy, err := st.CreateCycle(ctx, app.RebuildCycle{ReleaseID: "rel-1", OriginEventID: "env-1", BaselineSBOMID: "", LastSBOMID: "",
		Targeted: []string{"CVE-2026-1"}, Attempts: 1, State: app.CycleOpen, OpenedAt: epoch, UpdatedAt: epoch,
		Origin: app.CycleOriginDecision, DecisionID: "dec-1", Decision: decision, ProductID: "prod-1", ProjectID: "proj-1"})
	if err != nil {
		t.Fatalf("create cycle: %v", err)
	}
	if cy.Origin != app.CycleOriginDecision || string(cy.Decision) != string(decision) || cy.ProductID != "prod-1" || cy.Joined == nil || len(cy.Joined) != 0 {
		t.Fatalf("cycle = %+v", cy)
	}
	// A cycle that names no origin is one the posture opened.
	old, err := st.CreateCycle(ctx, app.RebuildCycle{ReleaseID: "rel-2", BaselineSBOMID: "ev-1", LastSBOMID: "ev-1",
		Targeted: []string{"CVE-2026-2"}, Attempts: 1, State: app.CycleOpen, OpenedAt: epoch, UpdatedAt: epoch})
	if err != nil || old.Origin != app.CycleOriginEvaluation || old.Decision != nil {
		t.Fatalf("evaluation cycle = %+v (err %v)", old, err)
	}

	cy.Refusals, cy.Joined, cy.State, cy.ClosedBy, cy.ClosedNote = 2, []string{"dec-2"}, app.CycleStopped, "pat", "note"
	if err := st.UpdateCycle(ctx, cy); err != nil {
		t.Fatalf("update cycle: %v", err)
	}
	got, found, err := st.CycleByID(ctx, cy.ID)
	if err != nil || !found || got.Refusals != 2 || !reflect.DeepEqual(got.Joined, []string{"dec-2"}) || got.State != app.CycleStopped || got.ClosedBy != "pat" || got.ClosedNote != "note" {
		t.Fatalf("by id = %+v found=%t err=%v", got, found, err)
	}
	if latest, found, err := st.LatestCycle(ctx, "rel-1"); err != nil || !found || latest.ID != cy.ID {
		t.Errorf("latest = %+v found=%t err=%v", latest, found, err)
	}
	if _, found, err := st.LatestCycle(ctx, "rel-none"); err != nil || found {
		t.Errorf("latest of nothing: found=%t err=%v", found, err)
	}
	if _, found, err := st.CycleByID(ctx, 99999); err != nil || found {
		t.Errorf("unknown id: found=%t err=%v", found, err)
	}
	for _, state := range []string{app.CycleRefused, app.CycleStopped} {
		got.State = state
		if err := st.UpdateCycle(ctx, got); err != nil {
			t.Errorf("state %s refused by the check: %v", state, err)
		}
	}

	// D21: a closed cycle that decisions joined is written to the outbox for Governance.
	if err := st.CycleClosed(ctx, got); err != nil {
		t.Fatalf("cycle closed: %v", err)
	}
	var eventType, schemaRef, subject, payload string
	if err := pool.QueryRow(ctx, `SELECT event_type, schema_ref, subject, payload::text FROM communication_outbox`).Scan(&eventType, &schemaRef, &subject, &payload); err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	if eventType != app.EventRebuildCycleClosed || schemaRef != "communication.rebuild_cycle_closed.v1" || subject != "rel-1" ||
		!strings.Contains(payload, `"dec-2"`) || !strings.Contains(payload, `"stopped"`) {
		t.Errorf("outbox row: %s %s %s %s", eventType, schemaRef, subject, payload)
	}

	// Requests.
	hook := pendingIntent(intentID1, app.IntentWebhook, "rebuild:1:1:1", epoch)
	jenkins := pendingIntent(intentID2, app.IntentCIRebuild, "rebuild:1:1:2", epoch)
	for _, in := range []app.Intent{hook, jenkins} {
		if _, err := st.CreateIntent(ctx, in); err != nil {
			t.Fatalf("create intent: %v", err)
		}
	}
	first := app.RebuildRequest{IntentID: intentID1, CycleID: cy.ID, ReleaseID: "rel-1", DecisionID: "dec-1", Attempt: 1, Try: 1,
		Channel: app.ChannelWebhook, State: app.RequestRequested, RequestedAt: epoch}
	second := first
	second.IntentID, second.Try, second.Channel = intentID2, 2, app.ChannelJenkins
	for _, r := range []app.RebuildRequest{first, second, first} { // the repeat stores nothing
		if err := st.CreateRequest(ctx, r); err != nil {
			t.Fatalf("create request: %v", err)
		}
	}
	clash := first
	clash.IntentID = "another-intent"
	if err := st.CreateRequest(ctx, clash); err == nil {
		t.Error("a second request for the same cycle, attempt and try must be refused")
	}
	list, err := st.ListRequests(ctx, cy.ID)
	if err != nil || len(list) != 2 || list[0].IntentID != intentID1 || list[1].Try != 2 || !list[0].RequestedAt.Equal(epoch) || !list[0].DeliveredAt.IsZero() {
		t.Fatalf("list = %+v (err %v)", list, err)
	}
	if latest, found, err := st.LatestRequest(ctx, cy.ID); err != nil || !found || latest.IntentID != intentID2 {
		t.Errorf("latest request = %+v found=%t err=%v", latest, found, err)
	}
	if _, found, err := st.LatestRequest(ctx, 99999); err != nil || found {
		t.Errorf("latest of no cycle: found=%t err=%v", found, err)
	}
	if _, err := st.RequestByIntent(ctx, "nope"); !errors.Is(err, app.ErrRebuildRequestNotFound) {
		t.Errorf("unknown request = %v", err)
	}
	if _, ok, err := st.LastDeliveredAt(ctx, "rel-1"); err != nil || ok {
		t.Errorf("nothing delivered yet: ok=%t err=%v", ok, err)
	}

	// D25 and D43: the delivered intent takes its request along.
	for _, id := range []string{intentID1, intentID2} {
		if err := st.MarkDelivered(ctx, id, map[string]string{"transport": "x"}); err != nil {
			t.Fatalf("mark delivered: %v", err)
		}
	}
	a, _ := st.RequestByIntent(ctx, intentID1)
	b, _ := st.RequestByIntent(ctx, intentID2)
	if a.State != app.RequestDelivered || a.DeliveredAt.IsZero() || b.State != app.RequestSubmitted || b.DeliveredAt.IsZero() {
		t.Fatalf("after delivery: %+v / %+v", a, b)
	}
	if at, ok, err := st.LastDeliveredAt(ctx, "rel-1"); err != nil || !ok || at.IsZero() {
		t.Errorf("last delivered: %v ok=%t err=%v", at, ok, err)
	}
	// An intent that is no longer pending moves nothing.
	a.State = app.RequestRequested
	_ = st.UpdateRequest(ctx, a)
	if err := st.MarkDelivered(ctx, intentID1, nil); err == nil {
		t.Error("marking a delivered intent delivered again must be refused")
	}
	if a, _ = st.RequestByIntent(ctx, intentID1); a.State != app.RequestRequested {
		t.Errorf("a refused transition must not move the request: %s", a.State)
	}

	// The silent sweep's read: webhook requests still delivered since before the limit.
	a.State, a.DeliveredAt = app.RequestDelivered, epoch
	a.Reason, a.BuildRef, a.ReportedBy, a.StatusAt, a.ExecutionStartedAt = "r", "queue/1", "key:x", epoch, epoch
	a.SettledAnswer, a.SettledBy, a.SettledAt, a.SettleNote = "submitted", "pat", epoch, "n"
	if err := st.UpdateRequest(ctx, a); err != nil {
		t.Fatalf("update request: %v", err)
	}
	back, _ := st.RequestByIntent(ctx, intentID1)
	a.RequestedAt = back.RequestedAt
	if !reflect.DeepEqual(back, a) {
		t.Errorf("request round trip:\n got %+v\nwant %+v", back, a)
	}
	silent, err := st.SilentRequests(ctx, epoch.Add(time.Hour))
	if err != nil || len(silent) != 1 || silent[0].IntentID != intentID1 {
		t.Errorf("silent = %+v (err %v)", silent, err)
	}
	if silent, _ = st.SilentRequests(ctx, epoch.Add(-time.Hour)); len(silent) != 0 {
		t.Errorf("nothing is silent before it was delivered: %+v", silent)
	}

	// Holds: one row per Release, replaced, read, removed.
	if _, held, err := st.Hold(ctx, "rel-1"); err != nil || held {
		t.Errorf("no hold yet: held=%t err=%v", held, err)
	}
	until := epoch.Add(time.Hour)
	for _, h := range []app.RebuildHold{
		{ReleaseID: "rel-1", DecisionID: "dec-8", Reason: app.HoldUnsignedRoute, RecordedAt: epoch},
		{ReleaseID: "rel-1", DecisionID: "dec-9", Reason: app.HoldCoolDown, Until: until, RecordedAt: epoch},
	} {
		if err := st.SaveHold(ctx, h); err != nil {
			t.Fatalf("save hold: %v", err)
		}
	}
	if h, held, err := st.Hold(ctx, "rel-1"); err != nil || !held || h.DecisionID != "dec-9" || h.Reason != app.HoldCoolDown || !h.Until.Equal(until) || !h.RecordedAt.Equal(epoch) {
		t.Errorf("hold = %+v held=%t err=%v", h, held, err)
	}
	if err := st.ClearHold(ctx, "rel-1"); err != nil {
		t.Fatalf("clear hold: %v", err)
	}
	if _, held, _ := st.Hold(ctx, "rel-1"); held {
		t.Error("the hold must be gone")
	}

	// The last evaluated SBOM.
	if id, err := st.LastSBOM(ctx, "rel-1"); err != nil || id != "" {
		t.Errorf("no sbom yet: %q err=%v", id, err)
	}
	for _, id := range []string{"sbom-1", "sbom-2"} {
		if err := st.SaveLastSBOM(ctx, "rel-1", id, epoch); err != nil {
			t.Fatalf("save sbom: %v", err)
		}
	}
	if id, err := st.LastSBOM(ctx, "rel-1"); err != nil || id != "sbom-2" {
		t.Errorf("last sbom = %q err=%v", id, err)
	}
}

// A closed pool makes every read and write fail, and each failure is returned.
func TestRebuildRequestsStore_Failures(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.ListRequests(ctx, 1); err == nil {
		t.Error("list on a cancelled context must fail")
	}
	if _, _, err := st.LastDeliveredAt(ctx, "rel-1"); err == nil {
		t.Error("last delivered on a cancelled context must fail")
	}
	if _, _, err := st.Hold(ctx, "rel-1"); err == nil {
		t.Error("hold on a cancelled context must fail")
	}
	if _, _, err := st.LatestRequest(ctx, 1); err == nil {
		t.Error("latest request on a cancelled context must fail")
	}
}
