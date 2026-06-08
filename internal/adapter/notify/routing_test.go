package notify

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestNormalizeEventType(t *testing.T) {
	cases := map[string]string{
		"ingestion":                          domain.NotificationEventIngestionCompleted,
		"INGESTION_COMPLETE":               domain.NotificationEventIngestionCompleted,
		domain.NotificationEventIngestionRejected: domain.NotificationEventIngestionRejected,
		domain.NotificationEventCVEWatchFinding:   domain.NotificationEventCVEWatchFinding,
		domain.NotificationEventTriageDecision:    domain.NotificationEventTriageDecision,
		domain.NotificationEventVEXUpdated:        domain.NotificationEventVEXUpdated,
		"custom":                             "custom",
	}
	for in, want := range cases {
		if got := normalizeEventType(in); got != want {
			t.Fatalf("%q => %q, want %q", in, got, want)
		}
	}
}

func TestRuleMatchesDisabled(t *testing.T) {
	rule := domain.NotificationRule{Enabled: false, EventType: domain.NotificationEventIngestionCompleted}
	if ruleMatchesEvent(rule, domain.NotificationEvent{Type: domain.NotificationEventIngestionCompleted}) {
		t.Fatal("disabled rule should not match")
	}
}

func TestFindingsMeetSeverity(t *testing.T) {
	if findingsMeetSeverity([]domain.NotificationFinding{{Severity: "LOW"}}, severityRank["high"]) {
		t.Fatal("low should not meet high threshold")
	}
	if !findingsMeetSeverity([]domain.NotificationFinding{{Severity: "CRITICAL"}}, severityRank["high"]) {
		t.Fatal("critical should meet high threshold")
	}
}
