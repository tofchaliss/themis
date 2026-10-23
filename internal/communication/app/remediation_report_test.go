package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
)

type repReader struct {
	rep     app.RemediationReport
	err     error
	product string
}

func (r *repReader) RemediationMetrics(_ context.Context, product, tag string) (app.RemediationReport, error) {
	r.product = product + "|" + tag
	return r.rep, r.err
}

type repRenderer struct{ format string }

func (r *repRenderer) RenderRemediation(_ app.RemediationReport, format string) ([]byte, string, error) {
	r.format = format
	return []byte(format), "text/" + format, nil
}

func TestRemediationReports_Render(t *testing.T) {
	ctx := context.Background()
	reader, renderer := &repReader{}, &repRenderer{}
	reps := app.NewRemediationReports(reader, renderer)
	if b, ct, err := reps.Render(ctx, "Gateway", "env:prod", ""); err != nil || string(b) != "markdown" || ct != "text/markdown" || reader.product != "Gateway|env:prod" {
		t.Fatalf("default = %s %s %v", b, ct, err)
	}
	if b, _, err := reps.Render(ctx, "", "", " JSON "); err != nil || string(b) != "json" {
		t.Fatalf("json = %s %v", b, err)
	}
	if _, _, err := reps.Render(ctx, "", "", "pdf"); !errors.Is(err, app.ErrUnknownReportFormat) {
		t.Fatalf("pdf = %v", err)
	}
	reader.err = errors.New("governance down")
	if _, _, err := reps.Render(ctx, "", "", "json"); err == nil {
		t.Fatal("read error swallowed")
	}
}

func TestMetricsSchedule(t *testing.T) {
	ctx := context.Background()
	reader := &repReader{rep: app.RemediationReport{
		Estate: app.RemediationMetrics{Open: 9, WithinSLA: 5, SLAApplicable: 7, BreachedNow: 2, TimeToDecision: app.MeanDays{MeanDays: 3.25, Count: 4}},
		Products: []app.RemediationMetrics{{Scope: "Portal", BreachedNow: 1}, {Scope: "Gateway", BreachedNow: 4}, {Scope: "Quiet"},
			{Scope: "a", BreachedNow: 1}, {Scope: "b", BreachedNow: 1}, {Scope: "c", BreachedNow: 1}, {Scope: "d", BreachedNow: 1}},
	}}
	// Unrouted: nothing is read or sent.
	unrouted := app.NewMetricsSchedule(reader, intentSvc(newIntentStore(), app.DeliveryIntentConfig{}), &intentIDs{})
	if sent, err := unrouted.Run(ctx); sent || err != nil || reader.product != "" {
		t.Fatalf("unrouted = %v %v", sent, err)
	}
	store := newIntentStore()
	svc := intentSvc(store, app.DeliveryIntentConfig{WebhookRoutes: map[string]string{app.WebhookRemediationMetrics: "slack-sec"}})
	m := app.NewMetricsSchedule(reader, svc, &intentIDs{})
	sent, err := m.Run(ctx)
	if err != nil || !sent || len(store.created) != 1 {
		t.Fatalf("run = %v %v", sent, err)
	}
	s := store.created[0].Snapshot
	if s[app.SnapshotMetricsOpen] != "9" || s[app.SnapshotMetricsBreached] != "2" || s[app.SnapshotMetricsDecision] != "3.2" ||
		s[app.SnapshotMetricsWorst] != "Gateway=4,Portal=1,a=1,b=1,c=1" || store.created[0].ProductID != "estate" {
		t.Fatalf("snapshot = %v", s)
	}
	// No decision sample: the key is left out.
	reader.rep.Estate.TimeToDecision = app.MeanDays{}
	store2 := newIntentStore()
	if _, err := app.NewMetricsSchedule(reader, intentSvc(store2, app.DeliveryIntentConfig{WebhookRoutes: map[string]string{app.WebhookRemediationMetrics: "x"}}), &intentIDs{}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := store2.created[0].Snapshot[app.SnapshotMetricsDecision]; ok {
		t.Fatal("decision mean without a sample")
	}
	reader.err = errors.New("governance down")
	if _, err := m.Run(ctx); err == nil {
		t.Fatal("read error swallowed")
	}
}

func TestMetricsSchedule_RunEvery(t *testing.T) {
	reader := &repReader{}
	m := app.NewMetricsSchedule(reader, intentSvc(newIntentStore(), app.DeliveryIntentConfig{WebhookRoutes: map[string]string{app.WebhookRemediationMetrics: "x"}}), &intentIDs{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 1)
	go m.RunEvery(ctx, time.Millisecond, func(sent bool, _ error) {
		if sent {
			select {
			case done <- struct{}{}:
			default:
			}
			cancel()
		}
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("never sent")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel2()
	m.RunEvery(ctx2, time.Millisecond, nil)
}
