package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

func TestWebhookHealthLadder(t *testing.T) {
	t0 := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	h := domain.NewWebhookHealth("slack")
	if h.State != domain.WebhookActive || !h.MaySend(t0) {
		t.Fatalf("new = %+v", h)
	}
	h = h.Failed(t0, "503")
	if h.State != domain.WebhookActiveTmp || !h.MaySend(t0) || h.LastError != "503" {
		t.Fatalf("one failure = %+v", h)
	}
	h = h.Failed(t0, "503").Failed(t0, "503")
	if h.State != domain.WebhookInactiveTmp || h.Pauses != 1 || h.MaySend(t0.Add(30*time.Minute)) || !h.MaySend(t0.Add(domain.WebhookPause)) {
		t.Fatalf("paused = %+v", h)
	}
	// The try after the pause fails: paused again, then once more and it is disabled.
	h = h.Failed(t0.Add(time.Hour), "timeout")
	if h.State != domain.WebhookInactiveTmp || h.Pauses != 2 || !h.PausedUntil.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("second pause = %+v", h)
	}
	h = h.Failed(t0.Add(2*time.Hour), "timeout")
	if h.State != domain.WebhookInactivePermanent || h.MaySend(t0.Add(100*time.Hour)) || !h.PausedUntil.IsZero() {
		t.Fatalf("disabled = %+v", h)
	}
	r := h.Reenabled()
	if r.State != domain.WebhookActive || r.ConsecutiveFailures != 0 || r.LastError != "timeout" {
		t.Fatalf("re-enabled = %+v", r)
	}
	ok := h.Succeeded(t0.Add(200 * time.Hour))
	if ok.State != domain.WebhookActive || ok.ConsecutiveFailures != 0 || ok.LastError != "" || !ok.LastSuccessAt.Equal(t0.Add(200*time.Hour)) {
		t.Fatalf("success = %+v", ok)
	}
	for _, s := range []domain.WebhookHealthState{domain.WebhookActive, domain.WebhookActiveTmp, domain.WebhookInactiveTmp, domain.WebhookInactivePermanent} {
		if !domain.ValidWebhookHealthState(s) {
			t.Errorf("%s invalid", s)
		}
	}
	if domain.ValidWebhookHealthState("broken") {
		t.Error("broken is valid")
	}
}
