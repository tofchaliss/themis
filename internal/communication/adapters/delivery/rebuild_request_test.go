package delivery_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/app"
)

func rebuildRequestIntent(dest string) app.Intent {
	return app.Intent{ID: "int-r", Type: app.IntentWebhook, Destination: dest,
		Snapshot:     map[string]string{app.SnapshotWebhookEvent: app.WebhookRebuildRequested},
		PayloadBytes: app.BuildPayload("rebuild", []byte(`{"specversion":"1.0","id":"int-r"}`))}
}

// D6 and D36: a rebuild request goes out signed and exactly as stored, whatever the audience's
// format says; an audience with no secret gets nothing, and its health is not spent.
func TestRealWebhookDeliverer_RebuildRequestIsSignedAndSentAsStored(t *testing.T) {
	var gotBody, gotSig string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotSig = string(b), r.Header.Get(delivery.SignatureHeader)
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	health := &memHealth{}
	d, err := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{
		Targets: map[string]string{"builders": srv.URL, "open": srv.URL},
		Secrets: map[string]string{"builders": "k"},
		Formats: map[string]string{"builders": delivery.WebhookFormatTeams},
	}, health, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeliverIntent(context.Background(), rebuildRequestIntent("builders")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if gotBody != `{"specversion":"1.0","id":"int-r"}` || gotSig != delivery.Sign("k", []byte(gotBody)) {
		t.Fatalf("body=%q sig=%q", gotBody, gotSig)
	}
	res, err := d.DeliverIntent(context.Background(), rebuildRequestIntent("open"))
	if err == nil || !strings.Contains(err.Error(), "never sent unsigned") || !strings.Contains(err.Error(), "THEMIS_COMMUNICATION_WEBHOOK_SECRET_OPEN") ||
		!strings.Contains(res.Excerpt, "unsigned") || calls != 1 {
		t.Fatalf("unsigned: res=%+v err=%v calls=%d", res, err, calls)
	}
	if _, recorded := health.byDest["open"]; recorded {
		t.Error("a request that was never sent must not move the destination's health")
	}
}

func TestWebhookConfig_SignedAudiencesAndUnsignedRebuildRoutes(t *testing.T) {
	cfg := delivery.WebhookConfig{Secrets: map[string]string{"builders": "k", "empty": ""}}
	if got := cfg.SignedAudiences(); !reflect.DeepEqual(got, map[string]bool{"builders": true}) {
		t.Errorf("signed = %v", got)
	}
	routes := map[string]string{
		app.WebhookRebuildRequested: "builders", app.WebhookRebuildRequested + "#edge": "open",
		app.WebhookRebuildRequested + "#core": "empty", app.WebhookReleaseEvaluated: "open",
	}
	if got := cfg.UnsignedRebuildRoutes(routes); !reflect.DeepEqual(got, []string{"rebuild_requested#core=empty", "rebuild_requested#edge=open"}) {
		t.Errorf("unsigned routes = %v", got)
	}
	if got := cfg.UnsignedRebuildRoutes(map[string]string{app.WebhookRebuildRequested: "builders"}); len(got) != 0 {
		t.Errorf("a signed route is not unsigned: %v", got)
	}
}

func TestConfig_RebuildOpenFrom(t *testing.T) {
	if s := (delivery.Config{}).String(); !strings.Contains(s, "rebuild_open_from=evaluation") {
		t.Errorf("default not shown: %s", s)
	}
	t.Setenv("THEMIS_COMMUNICATION_REBUILD_OPEN_FROM", "decision")
	cfg := delivery.ConfigFromEnv()
	if cfg.RebuildOpenFrom != app.RebuildOpenFromDecision || !strings.Contains(cfg.String(), "rebuild_open_from=decision") {
		t.Errorf("cfg = %s", cfg)
	}
	// An unknown value is the rule before step R3, never a third behaviour.
	for value, want := range map[string]string{"decision": app.RebuildOpenFromDecision, "posture": app.RebuildOpenFromEvaluation, "": app.RebuildOpenFromEvaluation} {
		h := newHarness(t, delivery.Config{Enabled: true, RebuildOpenFrom: value})
		if got := h.worker.ConfigForTest().RebuildOpenFrom; got != want {
			t.Errorf("%q -> %q, want %q", value, got, want)
		}
	}
}

type sweeperStub struct {
	n     int
	err   error
	calls chan struct{}
}

func (s *sweeperStub) SweepSilent(context.Context) (int, error) {
	if s.calls != nil {
		select {
		case s.calls <- struct{}{}:
		default:
		}
	}
	return s.n, s.err
}

// D28 item 3: the sweep runs beside the delivery loop, says what it did, and a failure is logged
// and not fatal.
func TestWorker_SilentRequestSweep(t *testing.T) {
	h := newHarness(t, testConfig())
	sw := &sweeperStub{n: 2}
	h.worker.WithRebuildSweep(sw)
	h.worker.SweepSilentForTest(context.Background())
	if !hasMessage(h.logs, "marked uncertain") {
		t.Error("a sweep that changed requests must say so")
	}
	sw.n, sw.err = 0, errors.New("db down")
	h.worker.SweepSilentForTest(context.Background())
	if !hasMessage(h.logs, "silent-request sweep failed") {
		t.Error("a failed sweep must be logged")
	}

	// The loop ticks and stops with the context.
	sw.err, sw.calls = nil, make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.worker.RunSilentSweepForTest(ctx, time.Millisecond); close(done) }()
	select {
	case <-sw.calls:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep loop did not tick")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweep loop did not stop")
	}

	// Run starts it with the worker.
	ctx, cancel = context.WithCancel(context.Background())
	go h.worker.Run(ctx)
	time.Sleep(5 * time.Millisecond)
	cancel()
}
