package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/http/gen"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

type healthList struct {
	hs  []domain.WebhookHealth
	err error
}

func (h healthList) WebhookHealth(context.Context, string) (domain.WebhookHealth, error) {
	return domain.WebhookHealth{}, nil
}
func (h healthList) SaveWebhookHealth(context.Context, domain.WebhookHealth, time.Time) error { return nil }
func (h healthList) ListWebhookHealth(context.Context) ([]domain.WebhookHealth, error)        { return h.hs, h.err }

func healthServer(t *testing.T, s app.WebhookHealthStore) *httptest.Server {
	t.Helper()
	repo := &memRepo{}
	write := app.NewPublicationService(repo, nil, nil, nil, nil)
	read := app.NewReadService(repo, nil, nil)
	h := commhttp.NewHandler(write, read)
	if s != nil {
		h = h.WithWebhookHealth(s)
	}
	srv := httptest.NewServer(h.Router())
	t.Cleanup(srv.Close)
	return srv
}

func TestGetWebhookHealth(t *testing.T) {
	at := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	srv := healthServer(t, healthList{hs: []domain.WebhookHealth{
		{Destination: "slack-sec", State: domain.WebhookInactiveTmp, ConsecutiveFailures: 3, PausedUntil: at, LastFailureAt: at, LastError: "500"},
		{Destination: "teams", State: domain.WebhookActive, LastSuccessAt: at},
	}})
	code, body := do(t, http.MethodGet, srv.URL+"/webhook-health", nil)
	var got []gen.WebhookHealth
	if code != http.StatusOK || json.Unmarshal(body, &got) != nil || len(got) != 2 {
		t.Fatalf("health = %d %s", code, body)
	}
	if got[0].State != "inactive_tmp" || got[0].PausedUntil == nil || got[0].LastError == nil || got[0].LastSuccessAt != nil ||
		got[1].State != "active" || got[1].LastError != nil || got[1].LastSuccessAt == nil {
		t.Fatalf("rows = %s", body)
	}
	if code, _ := do(t, http.MethodGet, healthServer(t, healthList{err: errors.New("db")}).URL+"/webhook-health", nil); code != http.StatusInternalServerError {
		t.Fatalf("error = %d", code)
	}
	if code, _ := do(t, http.MethodGet, healthServer(t, nil).URL+"/webhook-health", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("unwired = %d", code)
	}
}
