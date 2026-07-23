package notify

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func channelEvent() domain.NotificationEvent {
	return domain.NotificationEvent{
		Type:        domain.NotificationEventCVEWatchFinding,
		ProductName: "acme",
		ProductID:   "p1",
		CVEID:       "CVE-2024-1",
		Findings: []domain.NotificationFinding{
			{CVEID: "CVE-2024-1", ComponentPURL: "pkg:npm/x", Severity: "high", EffectiveState: "detected"},
		},
	}
}

func TestDeliverChannelsViaFakePoster(t *testing.T) {
	var gotURL string
	var gotBody []byte
	svc := testService(t, &stubRules{}, func(s *Service) {
		s.httpPost = func(_ context.Context, _ *http.Client, url string, body []byte) (int, error) {
			gotURL, gotBody = url, body
			return 200, nil
		}
	})
	ctx := context.Background()
	event := channelEvent()

	if err := svc.deliverSlack(ctx, "https://hooks.slack/x", event); err != nil {
		t.Fatal(err)
	}
	if gotURL != "https://hooks.slack/x" || !strings.Contains(string(gotBody), `"text"`) {
		t.Fatalf("slack url=%s body=%s", gotURL, gotBody)
	}

	if err := svc.deliverGenericWebhook(ctx, "https://hook/x", event); err != nil {
		t.Fatal(err)
	}
	if gotURL != "https://hook/x" || !strings.Contains(string(gotBody), `"event_type"`) {
		t.Fatalf("generic url=%s body=%s", gotURL, gotBody)
	}

	if err := svc.deliverPagerDuty(ctx, "rk-123", event); err != nil {
		t.Fatal(err)
	}
	if gotURL != pagerDutyEventsURL || !strings.Contains(string(gotBody), "rk-123") {
		t.Fatalf("pagerduty url=%s body=%s", gotURL, gotBody)
	}
	if !strings.Contains(string(gotBody), `"severity":"error"`) {
		t.Fatalf("pagerduty severity missing: %s", gotBody)
	}
}

func TestDeliverChannelsEmptyDestination(t *testing.T) {
	svc := testService(t, &stubRules{})
	ctx := context.Background()
	if err := svc.deliverSlack(ctx, "", domain.NotificationEvent{}); err == nil {
		t.Fatal("slack: want error")
	}
	if err := svc.deliverGenericWebhook(ctx, "", domain.NotificationEvent{}); err == nil {
		t.Fatal("generic: want error")
	}
	if err := svc.deliverPagerDuty(ctx, "", domain.NotificationEvent{}); err == nil {
		t.Fatal("pagerduty: want error")
	}
}

func TestDeliverJSONWebhookRetryAndFailure(t *testing.T) {
	attempts := 0
	svc := testService(t, &stubRules{}, func(s *Service) {
		s.maxRetry = 1
		s.httpPost = func(_ context.Context, _ *http.Client, _ string, _ []byte) (int, error) {
			attempts++
			return 500, nil
		}
	})
	if err := svc.deliverSlack(context.Background(), "https://x", channelEvent()); err == nil {
		t.Fatal("want non-2xx failure")
	}
	if attempts != 2 {
		t.Fatalf("attempts=%d, want 2", attempts)
	}
}

func TestDeliverJSONWebhookMarshalError(t *testing.T) {
	orig := marshalTeamsPayload
	defer func() { marshalTeamsPayload = orig }()
	marshalTeamsPayload = func(map[string]any) ([]byte, error) { return nil, errors.New("boom") }
	svc := testService(t, &stubRules{}, func(s *Service) {
		s.httpPost = func(context.Context, *http.Client, string, []byte) (int, error) { return 200, nil }
	})
	if err := svc.deliverSlack(context.Background(), "https://x", channelEvent()); err == nil {
		t.Fatal("want marshal error")
	}
}

func TestDeliverJSONWebhookTransportError(t *testing.T) {
	svc := testService(t, &stubRules{}, func(s *Service) {
		s.httpPost = func(context.Context, *http.Client, string, []byte) (int, error) {
			return 0, errors.New("dial fail")
		}
	})
	if err := svc.deliverSlack(context.Background(), "https://x", channelEvent()); err == nil {
		t.Fatal("want transport error")
	}
}

func TestDispatchNewChannelsThroughRule(t *testing.T) {
	svc := testService(t, &stubRules{rules: []domain.NotificationRule{
		{Name: "gw", EventType: domain.NotificationEventIngestionCompleted, Channel: domain.NotificationChannelGenericWebhook, Destination: "https://hook", Enabled: true},
		{Name: "pd", EventType: domain.NotificationEventIngestionCompleted, Channel: domain.NotificationChannelPagerDuty, Destination: "rk", Enabled: true},
	}}, func(s *Service) {
		s.httpPost = func(context.Context, *http.Client, string, []byte) (int, error) { return 200, nil }
	})
	if err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted}); err != nil {
		t.Fatal(err)
	}
}

func TestPagerDutySeverity(t *testing.T) {
	for sev, want := range map[string]string{
		"critical": "critical", "high": "error", "medium": "warning", "low": "info",
	} {
		got := pagerDutySeverity(domain.NotificationEvent{
			Findings: []domain.NotificationFinding{{Severity: sev}},
		})
		if got != want {
			t.Errorf("pagerDutySeverity(%s)=%s, want %s", sev, got, want)
		}
	}
	if pagerDutySeverity(domain.NotificationEvent{}) != "info" {
		t.Fatal("no findings should be info")
	}
}
