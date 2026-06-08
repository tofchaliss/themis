package notify

import (
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestDigestAccumulator(t *testing.T) {
	acc := newDigestAccumulator()
	acc.add(domain.NotificationEvent{
		BatchKey: "b1", Type: domain.NotificationEventCVEWatchFinding,
		Findings: []domain.NotificationFinding{{CVEID: "CVE-1", Severity: "HIGH"}},
	})
	acc.add(domain.NotificationEvent{
		BatchKey: "b1",
		Findings: []domain.NotificationFinding{{CVEID: "CVE-2", Severity: "MEDIUM"}},
	})
	event, ok := acc.take("b1")
	if !ok || len(event.Findings) != 2 {
		t.Fatalf("event=%+v ok=%v", event, ok)
	}
	if _, ok := acc.take("b1"); ok {
		t.Fatal("batch should be removed")
	}
}

func TestDigestAccumulatorEmptyBatchKey(t *testing.T) {
	acc := newDigestAccumulator()
	acc.add(domain.NotificationEvent{Findings: []domain.NotificationFinding{{CVEID: "CVE-1"}}})
	if _, ok := acc.take(""); ok {
		t.Fatal("unexpected batch")
	}
}

func TestBuildEmailBodySingleEvent(t *testing.T) {
	_, body := buildEmailBody(domain.NotificationEvent{
		Type: domain.NotificationEventIngestionCompleted, ProductName: "Payments", ScanID: "scan-1",
	})
	if !strings.Contains(body, "Payments") || !strings.Contains(body, "scan-1") {
		t.Fatalf("body=%q", body)
	}
}

func TestBuildEmailBodyDigestWithProduct(t *testing.T) {
	_, body := buildEmailBody(domain.NotificationEvent{
		Type: domain.NotificationEventCVEWatchFinding, ProductName: "Payments",
		Findings: []domain.NotificationFinding{{CVEID: "CVE-1", Severity: "HIGH"}},
	})
	if !strings.Contains(body, "Product: Payments") {
		t.Fatalf("body=%q", body)
	}
}

func TestBuildEmailBodyDigest(t *testing.T) {
	subject, body := buildEmailBody(domain.NotificationEvent{
		Type: domain.NotificationEventCVEWatchFinding,
		Findings: []domain.NotificationFinding{
			{CVEID: "CVE-1", ComponentPURL: "pkg:npm/a", Severity: "CRITICAL", EffectiveState: "detected"},
			{CVEID: "CVE-2", ComponentPURL: "pkg:npm/b", Severity: "LOW", EffectiveState: "detected"},
		},
	})
	if subject == "" || !strings.Contains(body, "critical: 1") || !strings.Contains(body, "CVE-1") {
		t.Fatalf("subject=%q body=%q", subject, body)
	}
}

func TestBuildTeamsCard(t *testing.T) {
	card := buildTeamsCard(domain.NotificationEvent{
		Type: domain.NotificationEventTriageDecision,
		ProductName: "Payments",
		Message: "false positive recorded",
		Findings: []domain.NotificationFinding{{CVEID: "CVE-9", Severity: "HIGH", EffectiveState: "suppressed"}},
	})
	attachments, ok := card["attachments"].([]map[string]any)
	if !ok || len(attachments) == 0 {
		t.Fatalf("card=%v", card)
	}
}

func TestSeverityBreakdown(t *testing.T) {
	out := severityBreakdown([]domain.NotificationFinding{
		{Severity: "critical"}, {Severity: "high"}, {Severity: "high"}, {Severity: "low"},
	})
	if !strings.Contains(out, "critical: 1") || !strings.Contains(out, "high: 2") {
		t.Fatalf("out=%q", out)
	}
}
