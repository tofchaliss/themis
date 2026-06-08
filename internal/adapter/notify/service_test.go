package notify

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

type stubRules struct {
	rules []domain.NotificationRule
	err   error
}

func (s *stubRules) ListRules(context.Context) ([]domain.NotificationRule, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.rules, nil
}

func (s *stubRules) ReplaceRules(context.Context, []domain.NotificationRule) error {
	return nil
}

func testService(t *testing.T, rules *stubRules, opts ...func(*Service)) *Service {
	t.Helper()
	svc := NewService(ServiceConfig{
		Rules: rules,
		SMTP: SMTPSettings{
			Host:   "smtp.example.com",
			Port:   587,
			From:   "alerts@themis.local",
			UseTLS: true,
		},
		MaxRetry:  2,
		BaseDelay: time.Millisecond,
		Logger:    slog.New(slog.DiscardHandler),
	})
	svc.sleep = func(time.Duration) {}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func TestDispatchNoRulesRepo(t *testing.T) {
	svc := NewService(ServiceConfig{})
	if err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted}); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchListRulesError(t *testing.T) {
	svc := testService(t, &stubRules{err: errors.New("boom")})
	err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDispatchNoMatchingRules(t *testing.T) {
	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "other", EventType: domain.NotificationEventCVEWatchFinding, Channel: domain.NotificationChannelEmail, Destination: "a@b.c", Enabled: true,
	}}})
	if err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted}); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchUnsupportedChannel(t *testing.T) {
	var recorded []string
	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "bad", EventType: domain.NotificationEventIngestionCompleted, Channel: "pagerduty", Destination: "x", Enabled: true,
	}}}, func(s *Service) {
		s.recordMetric = func(channel, status string) { recorded = append(recorded, channel+":"+status) }
	})
	err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted})
	if err == nil {
		t.Fatal("expected unsupported channel error")
	}
}

func TestDispatchEmailSuccess(t *testing.T) {
	host, port := startMockSMTPServer(t, true)
	var recorded []string
	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "email", EventType: domain.NotificationEventIngestionCompleted, Channel: domain.NotificationChannelEmail, Destination: "ops@example.com", Enabled: true,
	}}}, func(s *Service) {
		s.smtp.Host = host
		s.smtp.Port = port
		s.smtp.UseTLS = false
		s.recordMetric = func(channel, status string) { recorded = append(recorded, channel+":"+status) }
	})
	if err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted}); err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0] != "email:success" {
		t.Fatalf("recorded=%v", recorded)
	}
}

func TestDispatchEmailRetryAndFailure(t *testing.T) {
	var recorded []string
	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "email", EventType: domain.NotificationEventIngestionCompleted, Channel: domain.NotificationChannelEmail, Destination: "ops@example.com", Enabled: true,
	}}}, func(s *Service) {
		s.smtp.Host = "127.0.0.1"
		s.smtp.Port = 1
		s.maxRetry = 1
		s.smtpDial = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}
		s.recordMetric = func(channel, status string) { recorded = append(recorded, channel+":"+status) }
	})
	err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted})
	if err == nil {
		t.Fatal("expected smtp failure")
	}
	joined := strings.Join(recorded, ",")
	if !strings.Contains(joined, "email:retried") || !strings.Contains(joined, "email:failure") {
		t.Fatalf("recorded=%v", recorded)
	}
}

func TestLogDeliveryRedactsPassword(t *testing.T) {
	var logged string
	logger := slog.New(slog.NewTextHandler(&logSink{&logged}, nil))
	svc := testService(t, &stubRules{}, func(s *Service) { s.logger = logger })
	svc.logDelivery("smtp delivered", channelTypeEmail, 0, "ops@example.com", "super-secret", nil)
	if strings.Contains(logged, "super-secret") {
		t.Fatalf("logged=%q", logged)
	}
}

type logSink struct {
	out *string
}

func (l *logSink) Write(p []byte) (int, error) {
	*l.out += string(p)
	return len(p), nil
}

func TestDispatchTeamsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var recorded []string
	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "teams", EventType: domain.NotificationEventCVEWatchFinding, Channel: domain.NotificationChannelWebhook, Destination: server.URL, Enabled: true,
	}}}, func(s *Service) {
		s.recordMetric = func(channel, status string) { recorded = append(recorded, channel+":"+status) }
	})
	event := domain.NotificationEvent{
		Type: domain.NotificationEventCVEWatchFinding,
		Findings: []domain.NotificationFinding{{
			CVEID: "CVE-2024-1", ComponentPURL: "pkg:npm/lodash", Severity: "HIGH", EffectiveState: "detected",
		}},
	}
	if err := svc.Dispatch(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if recorded[0] != "teams:success" {
		t.Fatalf("recorded=%v", recorded)
	}
}

func TestDispatchTeamsRetryAndFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	var recorded []string
	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "teams", EventType: domain.NotificationEventCVEWatchFinding, Channel: domain.NotificationChannelWebhook, Destination: server.URL, Enabled: true,
	}}}, func(s *Service) {
		s.maxRetry = 2
		s.recordMetric = func(channel, status string) { recorded = append(recorded, channel+":"+status) }
	})
	event := domain.NotificationEvent{
		Type: domain.NotificationEventCVEWatchFinding,
		Findings: []domain.NotificationFinding{{
			CVEID: "CVE-2024-1", Severity: "HIGH",
		}},
	}
	if err := svc.Dispatch(context.Background(), event); err == nil {
		t.Fatal("expected failure")
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d", attempts)
	}
	if !strings.Contains(strings.Join(recorded, ","), "teams:retried") || !strings.Contains(strings.Join(recorded, ","), "teams:failure") {
		t.Fatalf("recorded=%v", recorded)
	}
}

func TestDispatchSlackSkipped(t *testing.T) {
	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "slack", EventType: domain.NotificationEventIngestionCompleted, Channel: domain.NotificationChannelSlack, Destination: "#sec", Enabled: true,
	}}})
	if err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted}); err != nil {
		t.Fatal(err)
	}
}

func TestDigestBufferAndFlush(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := testService(t, &stubRules{rules: []domain.NotificationRule{{
		Name: "teams", EventType: domain.NotificationEventCVEWatchFinding, Channel: domain.NotificationChannelWebhook, Destination: server.URL, Enabled: true,
	}}})
	for i := 0; i < 3; i++ {
		if err := svc.Dispatch(context.Background(), domain.NotificationEvent{
			Type: domain.NotificationEventCVEWatchFinding, BatchKey: "cycle-1",
			Findings: []domain.NotificationFinding{{CVEID: "CVE-" + string(rune('A'+i)), Severity: "HIGH"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.FlushDigest(context.Background(), "cycle-1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.FlushDigest(context.Background(), "missing"); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchMultipleRulesReturnsFirstError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := testService(t, &stubRules{rules: []domain.NotificationRule{
		{Name: "bad", EventType: domain.NotificationEventIngestionCompleted, Channel: "pagerduty", Destination: "x", Enabled: true},
		{Name: "teams", EventType: domain.NotificationEventIngestionCompleted, Channel: domain.NotificationChannelWebhook, Destination: server.URL, Enabled: true},
	}})
	err := svc.Dispatch(context.Background(), domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted})
	if err == nil {
		t.Fatal("expected first rule error")
	}
}

func TestRoutingFilters(t *testing.T) {
	rules := []domain.NotificationRule{
		{Name: "product", EventType: domain.NotificationEventCVEWatchFinding, Channel: domain.NotificationChannelWebhook, Destination: "http://example", Filter: domain.NotificationRuleFilter{ProductID: "prod-1"}, Enabled: true},
		{Name: "severity", EventType: domain.NotificationEventCVEWatchFinding, Channel: domain.NotificationChannelWebhook, Destination: "http://example", Filter: domain.NotificationRuleFilter{MinSeverity: "high"}, Enabled: true},
	}
	if len(matchingRules(rules, domain.NotificationEvent{Type: domain.NotificationEventCVEWatchFinding, ProductID: "prod-2", Findings: []domain.NotificationFinding{{Severity: "HIGH"}}})) != 1 {
		t.Fatal("expected one severity match")
	}
	if len(matchingRules(rules, domain.NotificationEvent{Type: domain.NotificationEventCVEWatchFinding, ProductID: "prod-1", Findings: []domain.NotificationFinding{{Severity: "LOW"}}})) != 1 {
		t.Fatal("expected product match without severity gate")
	}
	if len(matchingRules(rules, domain.NotificationEvent{Type: domain.NotificationEventCVEWatchFinding, Findings: []domain.NotificationFinding{{Severity: "LOW"}}})) != 0 {
		t.Fatal("expected no match")
	}
}
