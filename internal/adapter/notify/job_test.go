package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestJobHandlerDispatchAndFlush(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "teams", EventType: domain.NotificationEventCVEWatchFinding,
		Channel: domain.NotificationChannelWebhook, Destination: server.URL, Enabled: true,
	}}})

	handler := JobHandler(svc)
	event := domain.NotificationEvent{
		Type: domain.NotificationEventCVEWatchFinding, BatchKey: "batch-1",
		Findings: []domain.NotificationFinding{{CVEID: "CVE-1", Severity: "HIGH"}},
	}
	payload, _ := json.Marshal(notificationJobPayload{Event: event})
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeNotify, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	flushPayload, _ := json.Marshal(notificationJobPayload{FlushKey: "batch-1"})
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeNotify, Payload: flushPayload}); err != nil {
		t.Fatal(err)
	}
}

func TestJobHandlerInvalidPayload(t *testing.T) {
	handler := JobHandler(NewService(ServiceConfig{}))
	err := handler(context.Background(), domain.Job{Type: domain.JobTypeNotify, Payload: []byte("{")})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestJobHandlerNilService(t *testing.T) {
	handler := JobHandler(nil)
	if err := handler(context.Background(), domain.Job{Type: domain.JobTypeNotify, Payload: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
}
