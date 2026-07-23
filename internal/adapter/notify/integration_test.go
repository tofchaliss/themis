//go:build integration

package notify

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

func TestNotificationServiceIntegration(t *testing.T) {
	host, smtpPort := startMockSMTPServer(t, false)

	var teamsBodies []string
	var teamsMu sync.Mutex
	teamsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		teamsMu.Lock()
		teamsBodies = append(teamsBodies, string(body))
		teamsMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer teamsServer.Close()

	var logBuf bytes.Buffer
	var metricCalls []struct {
		channel string
		status  string
	}

	rules := &stubRules{rules: []domain.NotificationRule{
		{Name: "email-ingest", EventType: domain.NotificationEventIngestionCompleted, Channel: domain.NotificationChannelEmail, Destination: "ops@example.com", Enabled: true},
		{Name: "email-reject", EventType: domain.NotificationEventIngestionRejected, Channel: domain.NotificationChannelEmail, Destination: "ops@example.com", Enabled: true},
		{Name: "teams-watch", EventType: domain.NotificationEventCVEWatchFinding, Channel: domain.NotificationChannelWebhook, Destination: teamsServer.URL, Filter: domain.NotificationRuleFilter{MinSeverity: "high"}, Enabled: true},
		{Name: "teams-triage", EventType: domain.NotificationEventTriageDecision, Channel: domain.NotificationChannelWebhook, Destination: teamsServer.URL, Enabled: true},
		{Name: "teams-vex", EventType: domain.NotificationEventVEXUpdated, Channel: domain.NotificationChannelWebhook, Destination: teamsServer.URL, Enabled: true},
	}}

	svc := NewService(ServiceConfig{
		Rules: rules,
		SMTP: SMTPSettings{
			Host: host, Port: smtpPort, From: "alerts@themis.local", UseTLS: false,
		},
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
		Logger:    slog.New(slog.NewTextHandler(&logBuf, nil)),
		RecordMetric: func(channelType, status string) {
			metricCalls = append(metricCalls, struct {
				channel string
				status  string
			}{channelType, status})
		},
	})

	ctx := context.Background()
	events := []domain.NotificationEvent{
		{Type: domain.NotificationEventIngestionCompleted, ProductName: "Payments", ScanID: "scan-1"},
		{Type: domain.NotificationEventIngestionRejected, Message: "trust gate rejected"},
		{Type: domain.NotificationEventTriageDecision, ProductName: "Payments", Message: "false positive"},
		{Type: domain.NotificationEventVEXUpdated, Findings: []domain.NotificationFinding{{CVEID: "CVE-1", ComponentPURL: "pkg:npm/a", Severity: "HIGH", EffectiveState: "suppressed"}}},
	}
	for _, event := range events {
		if err := svc.Dispatch(ctx, event); err != nil {
			t.Fatalf("dispatch %s: %v", event.Type, err)
		}
	}

	for i := 0; i < 10; i++ {
		if err := svc.Dispatch(ctx, domain.NotificationEvent{
			Type: domain.NotificationEventCVEWatchFinding, BatchKey: "watch-cycle-1", ProductID: "prod-1",
			Findings: []domain.NotificationFinding{{
				CVEID: "CVE-2024-" + string(rune('A'+i)), ComponentPURL: "pkg:npm/lib", Severity: "HIGH", EffectiveState: "detected",
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.FlushDigest(ctx, "watch-cycle-1"); err != nil {
		t.Fatal(err)
	}

	teamsMu.Lock()
	defer teamsMu.Unlock()
	if len(teamsBodies) < 3 {
		t.Fatalf("teams bodies=%d", len(teamsBodies))
	}
	digestBody := teamsBodies[len(teamsBodies)-1]
	if !strings.Contains(digestBody, "CVE-2024-") || !strings.Contains(digestBody, "AdaptiveCard") {
		t.Fatalf("digest body=%s", digestBody)
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, teamsServer.URL) {
		t.Fatalf("webhook url leaked in logs: %s", logOutput)
	}
	if !strings.Contains(logOutput, "****") {
		t.Fatalf("expected redacted log output: %s", logOutput)
	}

	teamsSuccess := 0
	for _, call := range metricCalls {
		if call.channel == "teams" && call.status == "success" {
			teamsSuccess++
		}
	}
	if teamsSuccess < 3 {
		t.Fatalf("teams success metric=%v", teamsSuccess)
	}
}
