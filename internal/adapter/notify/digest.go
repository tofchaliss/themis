package notify

import (
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

type digestBatch struct {
	event domain.NotificationEvent
}

type digestAccumulator struct {
	batches map[string]*digestBatch
}

func newDigestAccumulator() *digestAccumulator {
	return &digestAccumulator{batches: make(map[string]*digestBatch)}
}

func (d *digestAccumulator) add(event domain.NotificationEvent) {
	if event.BatchKey == "" {
		return
	}
	batch, ok := d.batches[event.BatchKey]
	if !ok {
		batch = &digestBatch{event: event}
		batch.event.Findings = nil
		d.batches[event.BatchKey] = batch
	}
	batch.event.Findings = append(batch.event.Findings, event.Findings...)
}

func (d *digestAccumulator) take(batchKey string) (domain.NotificationEvent, bool) {
	batch, ok := d.batches[batchKey]
	if !ok {
		return domain.NotificationEvent{}, false
	}
	delete(d.batches, batchKey)
	return batch.event, true
}

func severityBreakdown(findings []domain.NotificationFinding) string {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	for _, finding := range findings {
		key := strings.ToLower(finding.Severity)
		if _, ok := counts[key]; ok {
			counts[key]++
		}
	}
	return fmt.Sprintf(
		"critical: %d, high: %d, medium: %d, low: %d",
		counts["critical"], counts["high"], counts["medium"], counts["low"],
	)
}

func buildEmailBody(event domain.NotificationEvent) (subject, body string) {
	subject = fmt.Sprintf("Themis notification: %s", normalizeEventType(event.Type))
	if len(event.Findings) == 0 {
		body = fmt.Sprintf(
			"Event: %s\nProduct: %s\nProject: %s\nScan: %s\nIngestion: %s\nMessage: %s\n",
			normalizeEventType(event.Type),
			event.ProductName,
			event.ProjectID,
			event.ScanID,
			event.IngestionID,
			event.Message,
		)
		return subject, body
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("Event: %s", normalizeEventType(event.Type)))
	if event.ProductName != "" {
		lines = append(lines, fmt.Sprintf("Product: %s", event.ProductName))
	}
	lines = append(lines, fmt.Sprintf("Severity breakdown: %s", severityBreakdown(event.Findings)))
	lines = append(lines, "Findings:")
	for _, finding := range event.Findings {
		lines = append(lines, fmt.Sprintf(
			"- %s on %s (%s, state=%s)",
			finding.CVEID,
			finding.ComponentPURL,
			finding.Severity,
			finding.EffectiveState,
		))
	}
	return subject, strings.Join(lines, "\n")
}

func buildTeamsCard(event domain.NotificationEvent) map[string]any {
	title := fmt.Sprintf("Themis: %s", normalizeEventType(event.Type))
	facts := []map[string]string{
		{"title": "Product", "value": event.ProductName},
		{"title": "Project", "value": event.ProjectID},
		{"title": "Scan", "value": event.ScanID},
	}
	if len(event.Findings) > 0 {
		facts = append(facts, map[string]string{
			"title": "Severity breakdown",
			"value": severityBreakdown(event.Findings),
		})
	}
	body := []map[string]any{
		{
			"type":   "TextBlock",
			"text":   title,
			"weight": "Bolder",
			"size":   "Medium",
		},
	}
	for _, fact := range facts {
		if fact["value"] == "" {
			continue
		}
		body = append(body, map[string]any{
			"type": "TextBlock",
			"text": fmt.Sprintf("%s: %s", fact["title"], fact["value"]),
		})
	}
	if event.Message != "" {
		body = append(body, map[string]any{
			"type": "TextBlock",
			"text": event.Message,
		})
	}
	for _, finding := range event.Findings {
		body = append(body, map[string]any{
			"type": "TextBlock",
			"text": fmt.Sprintf(
				"%s — %s (%s, %s)",
				finding.CVEID,
				finding.ComponentPURL,
				finding.Severity,
				finding.EffectiveState,
			),
		})
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body":    body,
				},
			},
		},
	}
}
