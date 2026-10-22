package delivery_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

type memHealth struct {
	mu      sync.Mutex
	byDest  map[string]domain.WebhookHealth
	readErr error
	saveErr error
}

func (m *memHealth) WebhookHealth(_ context.Context, d string) (domain.WebhookHealth, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readErr != nil {
		return domain.WebhookHealth{}, m.readErr
	}
	if h, ok := m.byDest[d]; ok {
		return h, nil
	}
	return domain.NewWebhookHealth(d), nil
}

func (m *memHealth) SaveWebhookHealth(_ context.Context, h domain.WebhookHealth, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byDest == nil {
		m.byDest = map[string]domain.WebhookHealth{}
	}
	m.byDest[h.Destination] = h
	return m.saveErr
}

func (m *memHealth) ListWebhookHealth(context.Context) ([]domain.WebhookHealth, error) { return nil, nil }

func webhookIntent(dest string) app.Intent {
	return app.Intent{ID: "int-w", Type: app.IntentWebhook, Destination: dest,
		Snapshot:     map[string]string{app.SnapshotWebhookEvent: app.WebhookReleaseEvaluated},
		PayloadBytes: app.BuildPayload("summary", []byte(`{"event":"release_evaluated","summary":"s","text":"s"}`))}
}

func TestParseWebhookPairsAndSecretEnv(t *testing.T) {
	got := delivery.ParseWebhookPairs(" slack-sec = https://hooks.example/a ; =x;novalue=; bad;teams=https://t.example/b\n")
	if len(got) != 2 || got["slack-sec"] != "https://hooks.example/a" || got["teams"] != "https://t.example/b" {
		t.Fatalf("pairs = %v", got)
	}
	if got := delivery.ParseWebhookPairs("a=https://x.example/\x01"); len(got) != 0 {
		t.Fatalf("control characters accepted: %v", got)
	}
	if got := delivery.ParseWebhookPairs("teams=https://t.example/b;ok=https://o.example"); len(got) != 2 {
		t.Fatalf("pairs = %v", got)
	}
	if e := delivery.WebhookSecretEnv("slack-sec.prod"); e != "THEMIS_COMMUNICATION_WEBHOOK_SECRET_SLACK_SEC_PROD" {
		t.Fatalf("env = %s", e)
	}
}

func TestWebhookConfigFromEnv(t *testing.T) {
	t.Setenv("THEMIS_COMMUNICATION_WEBHOOK_ENABLED", "1")
	t.Setenv("THEMIS_COMMUNICATION_WEBHOOK_TARGETS", "slack-sec=https://hooks.example/T0/B0/secretpath;teams=https://t.example/x")
	t.Setenv("THEMIS_COMMUNICATION_WEBHOOK_SECRET_SLACK_SEC", "s3cr3t")
	t.Setenv("THEMIS_COMMUNICATION_WEBHOOK_ROUTES", "release_evaluated=slack-sec;sla_breached=teams")
	t.Setenv("THEMIS_COMMUNICATION_SLA_DIGEST_INTERVAL", "12h")
	t.Setenv("THEMIS_COMMUNICATION_DASHBOARD_URL", "https://themis.example")
	cfg := delivery.ConfigFromEnv()
	if !cfg.Webhook.Enabled || len(cfg.Webhook.Targets) != 2 || cfg.Webhook.Secrets["slack-sec"] != "s3cr3t" || cfg.Webhook.Secrets["teams"] != "" ||
		cfg.WebhookRoutes["sla_breached"] != "teams" || cfg.SLADigestInterval != 12*time.Hour || cfg.DashboardURL != "https://themis.example" {
		t.Fatalf("cfg = %+v", cfg)
	}
	line := cfg.String()
	if strings.Contains(line, "secretpath") || strings.Contains(line, "s3cr3t") || !strings.Contains(line, "slack-sec->hooks.example(secret=set)") ||
		!strings.Contains(line, "teams->t.example(secret=unset)") {
		t.Fatalf("startup line leaks or omits: %s", line)
	}
}

func TestNewRealWebhookDeliverer_RefusesBadTargets(t *testing.T) {
	for name, targets := range map[string]map[string]string{
		"none":     nil,
		"cleartext": {"a": "http://hooks.example/x"},
		"relative": {"a": "/x"},
		"scheme":   {"a": "ftp://hooks.example/x"},
	} {
		if _, err := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{Enabled: true, Targets: targets}, nil, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{Targets: map[string]string{"a": "http://127.0.0.1:9/x", "b": "https://h.example"}}, nil, nil); err != nil {
		t.Fatalf("loopback http / https refused: %v", err)
	}
}

// One POST of the stored JSON body, signed when the audience has a secret, health recorded.
func TestRealWebhookDeliverer_PostsSignsAndRecordsHealth(t *testing.T) {
	var gotBody, gotSig, gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotSig, gotType = string(b), r.Header.Get(delivery.SignatureHeader), r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	health := &memHealth{}
	d, err := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{Targets: map[string]string{"slack-sec": srv.URL + "/hook"},
		Secrets: map[string]string{"slack-sec": "k"}}, health, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.DeliverIntent(context.Background(), webhookIntent("slack-sec"))
	if err != nil || res.StatusCode != 200 || res.Metadata["transport"] != "webhook" {
		t.Fatalf("deliver = %+v %v", res, err)
	}
	if !strings.HasPrefix(gotBody, `{"event":"release_evaluated"`) || gotType != "application/json" || gotSig != delivery.Sign("k", []byte(gotBody)) {
		t.Fatalf("request body=%q sig=%q type=%q", gotBody, gotSig, gotType)
	}
	if h := health.byDest["slack-sec"]; h.State != domain.WebhookActive || h.LastSuccessAt.IsZero() {
		t.Fatalf("health = %+v", h)
	}
}

// Three failures pause the destination; a paused destination is not called; a 4xx/5xx and a
// transport error both count, and neither leaks the URL path.
func TestRealWebhookDeliverer_FailuresPauseTheDestination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	health := &memHealth{}
	d, _ := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{Targets: map[string]string{"slack-sec": srv.URL + "/T0/secretpath"}}, health, nil)
	for i := 0; i < 3; i++ {
		res, err := d.DeliverIntent(context.Background(), webhookIntent("slack-sec"))
		if err == nil || res.StatusCode != 500 || strings.Contains(err.Error(), "secretpath") {
			t.Fatalf("attempt %d = %+v %v", i, res, err)
		}
	}
	if h := health.byDest["slack-sec"]; h.State != domain.WebhookInactiveTmp {
		t.Fatalf("after 3 failures = %+v", h)
	}
	if _, err := d.DeliverIntent(context.Background(), webhookIntent("slack-sec")); err == nil || calls != 3 || !strings.Contains(err.Error(), "inactive_tmp") {
		t.Fatalf("paused destination was called (%d) or not refused: %v", calls, err)
	}
	// Transport failure: the URL path never appears in the error.
	srv.Close()
	d2, _ := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{Targets: map[string]string{"x": srv.URL + "/T0/secretpath"}}, &memHealth{}, nil)
	if _, err := d2.DeliverIntent(context.Background(), webhookIntent("x")); err == nil || strings.Contains(err.Error(), "secretpath") {
		t.Fatalf("transport error = %v", err)
	}
}

func TestRealWebhookDeliverer_Refusals(t *testing.T) {
	d, _ := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{Targets: map[string]string{"a": "https://h.example/x"}}, &memHealth{readErr: errors.New("db")}, nil)
	in := webhookIntent("a")
	in.Type = app.IntentEmail
	if _, err := d.DeliverIntent(context.Background(), in); err == nil {
		t.Fatal("wrong type sent")
	}
	in = webhookIntent("a")
	in.PayloadBytes = nil
	if _, err := d.DeliverIntent(context.Background(), in); !errors.Is(err, delivery.ErrNoPayload) {
		t.Fatalf("no payload = %v", err)
	}
	if _, err := d.DeliverIntent(context.Background(), webhookIntent("unknown")); err == nil {
		t.Fatal("unknown audience sent")
	}
	if _, err := d.DeliverIntent(context.Background(), webhookIntent("a")); err == nil {
		t.Fatal("health read error swallowed")
	}
	// No health store, a bad URL that only fails at request time, and a save error that is logged.
	bad, _ := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{Targets: map[string]string{"a": "https://h.example/x"}}, nil, nil)
	bad.SetTargetForTest("a", "https://h.example/\x7f")
	if _, err := bad.DeliverIntent(context.Background(), webhookIntent("a")); err == nil {
		t.Fatal("bad request URL sent")
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer ok.Close()
	saving, _ := delivery.NewRealWebhookDeliverer(delivery.WebhookConfig{Targets: map[string]string{"a": ok.URL}}, &memHealth{saveErr: errors.New("db")}, nil)
	if _, err := saving.DeliverIntent(context.Background(), webhookIntent("a")); err != nil {
		t.Fatalf("a health save error must not fail the delivery: %v", err)
	}
}

func TestNewDeliverersWiresTheWebhookSender(t *testing.T) {
	ds := delivery.NewDeliverers(delivery.Config{Enabled: true}, nil, nil)
	if _, ok := ds[app.IntentWebhook].(*delivery.FakeWebhookDeliverer); !ok {
		t.Fatalf("default webhook sender = %T", ds[app.IntentWebhook])
	}
	bad := delivery.NewDeliverersWithHealth(delivery.Config{Enabled: true, Webhook: delivery.WebhookConfig{Enabled: true}}, nil, nil, nil)
	if _, ok := bad[app.IntentWebhook].(*delivery.FakeWebhookDeliverer); !ok {
		t.Fatalf("refused config must keep the fake: %T", bad[app.IntentWebhook])
	}
	real := delivery.NewDeliverersWithHealth(delivery.Config{Enabled: true, Webhook: delivery.WebhookConfig{Enabled: true,
		Targets: map[string]string{"a": "https://h.example"}}}, nil, &memHealth{}, nil)
	if _, ok := real[app.IntentWebhook].(*delivery.RealWebhookDeliverer); !ok {
		t.Fatalf("real webhook sender not wired: %T", real[app.IntentWebhook])
	}
}
