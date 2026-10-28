package delivery

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Receiver formats (D4, extended 2026-10-28 for the beta team's Microsoft Teams channel).
//
// A Slack incoming webhook renders the Themis document as it is, through its `text` field. A
// Teams channel does not: a Teams "Workflows" incoming webhook (the Office 365 connector it
// replaced is retired) accepts only a message carrying an Adaptive Card, and answers 400 or
// posts nothing to anything else. So the FORMAT of the body is a per-audience setting
// (THEMIS_COMMUNICATION_WEBHOOK_FORMATS="teams-sec=teams"), read at configure time beside the
// URL. The Themis document is still what is rendered and stored — the card is a re-shaping of
// it at the moment of sending, so the frozen field set stays the one contract, and the
// signature covers the bytes actually sent.

const (
	// WebhookFormatJSON posts the Themis document as it is (the default; Slack, any receiver).
	WebhookFormatJSON = "json"
	// WebhookFormatTeams wraps the document in a Microsoft Teams Adaptive Card message.
	WebhookFormatTeams = "teams"
)

// webhookFormats is the closed set of receiver formats.
var webhookFormats = map[string]bool{WebhookFormatJSON: true, WebhookFormatTeams: true}

// checkFormats refuses a format that is not in the closed set, or one for an audience that has
// no target — at configure time, so a typo fails the node's start rather than a send.
func (c WebhookConfig) checkFormats() error {
	for name, format := range c.Formats {
		if !webhookFormats[format] {
			return fmt.Errorf("delivery: webhook format %q for audience %q is not supported (use %s or %s)", format, name, WebhookFormatJSON, WebhookFormatTeams)
		}
		if _, ok := c.Targets[name]; !ok {
			return fmt.Errorf("delivery: webhook format set for audience %q, which has no target (THEMIS_COMMUNICATION_WEBHOOK_TARGETS)", name)
		}
	}
	return nil
}

// format names the receiver format of an audience; json when none is set.
func (c WebhookConfig) format(audience string) string {
	if f, ok := c.Formats[audience]; ok && f != "" {
		return f
	}
	return WebhookFormatJSON
}

// shapeBody re-shapes the stored Themis document for the audience's receiver. The json format
// returns the body untouched; teams returns the Adaptive Card message. A body that is not a
// Themis document (an N-M1a row with no JSON) is an error rather than a guess.
func (c WebhookConfig) shapeBody(audience string, body []byte) ([]byte, error) {
	switch c.format(audience) {
	case WebhookFormatTeams:
		return teamsMessage(body)
	default:
		return body, nil
	}
}

// webhookDocument mirrors the frozen field set of the serializer's WebhookDocument. Mirrored,
// not imported: the delivery adapter reads the stored bytes back, the same way a receiver does.
type webhookDocument struct {
	Event     string `json:"event"`
	Product   string `json:"product,omitempty"`
	Project   string `json:"project,omitempty"`
	Release   string `json:"release,omitempty"`
	ReleaseID string `json:"release_id,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
	Summary   string `json:"summary"`
	Link      string `json:"link,omitempty"`
}

// teamsEventTitles are the card titles per event kind; an unknown kind gets the kind itself.
var teamsEventTitles = map[string]string{
	"release_evaluated":   "Release evaluated",
	"rebuild_exhausted":   "Rebuild loop gave up",
	"review_due_soon":     "Review due soon",
	"disposition_stale":   "Decision needs another look",
	"sla_breached":        "SLA breached",
	"remediation_metrics": "Remediation metrics",
}

// teamsMessage wraps a Themis webhook document in the message shape a Teams Workflows
// incoming webhook accepts: one Adaptive Card (schema 1.4, the version Teams renders fully)
// with the summary, the identifying facts, and an "Open in Themis" button when there is a
// link. Nothing that is not in the document is invented.
func teamsMessage(body []byte) ([]byte, error) {
	var doc webhookDocument
	if err := json.Unmarshal(body, &doc); err != nil || strings.TrimSpace(doc.Summary) == "" {
		return nil, fmt.Errorf("webhook: body is not a Themis document, cannot shape it for teams")
	}
	title := teamsEventTitles[doc.Event]
	if title == "" {
		title = doc.Event
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"msteams": map[string]any{"width": "Full"},
	}
	elements := []map[string]any{
		{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "text": "Themis: " + title},
		{"type": "TextBlock", "wrap": true, "text": doc.Summary},
	}
	var facts []map[string]string
	for _, f := range []struct{ title, value string }{
		{"Product", doc.Product}, {"Project", doc.Project}, {"Release", doc.Release},
		{"Release id", doc.ReleaseID}, {"Finding id", doc.FindingID},
	} {
		if f.value != "" {
			facts = append(facts, map[string]string{"title": f.title, "value": f.value})
		}
	}
	if len(facts) > 0 {
		elements = append(elements, map[string]any{"type": "FactSet", "facts": facts})
	}
	card["body"] = elements
	if doc.Link != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open in Themis", "url": doc.Link}}
	}
	msg := map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
	}
	return json.Marshal(msg)
}
