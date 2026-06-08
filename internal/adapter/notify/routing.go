package notify

import (
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"unknown":  0,
}

func normalizeEventType(eventType string) string {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "ingestion", "ingestion_complete", domain.NotificationEventIngestionCompleted:
		return domain.NotificationEventIngestionCompleted
	case domain.NotificationEventIngestionRejected:
		return domain.NotificationEventIngestionRejected
	case domain.NotificationEventCVEWatchFinding:
		return domain.NotificationEventCVEWatchFinding
	case domain.NotificationEventTriageDecision:
		return domain.NotificationEventTriageDecision
	case domain.NotificationEventVEXUpdated:
		return domain.NotificationEventVEXUpdated
	default:
		return strings.ToLower(strings.TrimSpace(eventType))
	}
}

func ruleMatchesEvent(rule domain.NotificationRule, event domain.NotificationEvent) bool {
	if !rule.Enabled {
		return false
	}
	if normalizeEventType(rule.EventType) != normalizeEventType(event.Type) {
		return false
	}
	if rule.Filter.ProductID != "" && rule.Filter.ProductID != event.ProductID {
		return false
	}
	if rule.Filter.MinSeverity != "" && len(event.Findings) > 0 {
		minRank := severityRank[strings.ToLower(rule.Filter.MinSeverity)]
		if !findingsMeetSeverity(event.Findings, minRank) {
			return false
		}
	}
	return true
}

func findingsMeetSeverity(findings []domain.NotificationFinding, minRank int) bool {
	for _, finding := range findings {
		if severityRank[strings.ToLower(finding.Severity)] >= minRank {
			return true
		}
	}
	return false
}

func matchingRules(rules []domain.NotificationRule, event domain.NotificationEvent) []domain.NotificationRule {
	var matched []domain.NotificationRule
	for _, rule := range rules {
		if ruleMatchesEvent(rule, event) {
			matched = append(matched, rule)
		}
	}
	return matched
}
