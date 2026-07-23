package notify

import (
	"context"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

const (
	channelTypeSlack     = "slack"
	channelTypeWebhook   = "webhook"
	channelTypePagerDuty = "pagerduty"

	// pagerDutyEventsURL is the fixed PagerDuty Events API v2 enqueue endpoint;
	// the per-rule routing key travels in the payload, not the URL.
	pagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"
)

// deliverJSONWebhook POSTs a JSON payload to url with the shared retry, metrics,
// and logging wrapper used by every channel.
func (s *Service) deliverJSONWebhook(ctx context.Context, channelType, url string, payload map[string]any) error {
	err := withRetry(ctx, s.maxRetry, s.baseDelay, s.sleep, func(attempt int) {
		recordWith(s.recordMetric, channelType, "retried")
		s.logDelivery(channelType+" retry", channelType, attempt, redactURL(url), "", nil)
	}, func() error {
		body, mErr := marshalTeamsPayload(payload)
		if mErr != nil {
			return mErr
		}
		status, pErr := s.httpPost(ctx, s.httpClient, url, body)
		if pErr != nil {
			return pErr
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("%s endpoint returned status %d", channelType, status)
		}
		return nil
	})
	if err != nil {
		recordWith(s.recordMetric, channelType, "failure")
		s.logDelivery(channelType+" delivery failed", channelType, s.maxRetry, redactURL(url), "", err)
		return err
	}
	recordWith(s.recordMetric, channelType, "success")
	s.logDelivery(channelType+" delivered", channelType, 0, redactURL(url), "", nil)
	return nil
}

// deliverSlack posts a native Slack message ({"text": ...}) to an incoming webhook.
func (s *Service) deliverSlack(ctx context.Context, webhookURL string, event domain.NotificationEvent) error {
	if webhookURL == "" {
		return fmt.Errorf("slack webhook url not configured")
	}
	return s.deliverJSONWebhook(ctx, channelTypeSlack, webhookURL, buildSlackMessage(event))
}

// deliverGenericWebhook posts a clean structured JSON event to an arbitrary URL
// (as opposed to the Teams-card shape of the "webhook" channel).
func (s *Service) deliverGenericWebhook(ctx context.Context, url string, event domain.NotificationEvent) error {
	if url == "" {
		return fmt.Errorf("webhook url not configured")
	}
	return s.deliverJSONWebhook(ctx, channelTypeWebhook, url, buildGenericPayload(event))
}

// deliverPagerDuty triggers a PagerDuty Events API v2 alert; the rule's
// destination is the integration routing key.
func (s *Service) deliverPagerDuty(ctx context.Context, routingKey string, event domain.NotificationEvent) error {
	if routingKey == "" {
		return fmt.Errorf("pagerduty routing key not configured")
	}
	return s.deliverJSONWebhook(ctx, channelTypePagerDuty, pagerDutyEventsURL, buildPagerDutyPayload(routingKey, event))
}

func buildSlackMessage(event domain.NotificationEvent) map[string]any {
	subject, body := buildEmailBody(event)
	return map[string]any{"text": subject + "\n" + body}
}

func buildGenericPayload(event domain.NotificationEvent) map[string]any {
	subject, body := buildEmailBody(event)
	findings := make([]map[string]any, 0, len(event.Findings))
	for _, f := range event.Findings {
		findings = append(findings, map[string]any{
			"cve_id":          f.CVEID,
			"component_purl":  f.ComponentPURL,
			"severity":        f.Severity,
			"effective_state": f.EffectiveState,
		})
	}
	return map[string]any{
		"event_type":   event.Type,
		"product_id":   event.ProductID,
		"product_name": event.ProductName,
		"summary":      subject,
		"detail":       body,
		"findings":     findings,
	}
}

func buildPagerDutyPayload(routingKey string, event domain.NotificationEvent) map[string]any {
	subject, _ := buildEmailBody(event)
	return map[string]any{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":  subject,
			"source":   "themis",
			"severity": pagerDutySeverity(event),
			"custom_details": map[string]any{
				"event_type": event.Type,
				"product":    event.ProductName,
				"cve_id":     event.CVEID,
			},
		},
	}
}

// pagerDutySeverity maps the worst finding severity to a PagerDuty severity.
func pagerDutySeverity(event domain.NotificationEvent) string {
	worst := "info"
	for _, f := range event.Findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			return "critical"
		case "high":
			worst = "error"
		case "medium":
			if worst == "info" {
				worst = "warning"
			}
		}
	}
	return worst
}
