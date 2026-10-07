package serializer_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
)

// --- N-M1b: the outward-delivery payloads ---------------------------------------------------

// postureSource is a ReleaseSeverityReader double: it answers with the rows the ticket is
// rendered from, or fails, so the renderer is exercised against the port rather than against
// Governance.
type postureSource struct {
	rows []app.ReleaseSeverityRow
	err  error
	// calls counts the reads — one per ticket, never one per Finding.
	calls int
}

func (p *postureSource) ReleaseSeverity(context.Context, string) ([]app.ReleaseSeverityRow, error) {
	p.calls++
	return p.rows, p.err
}

// estate is the mixed population the counts and the lists are read off: two Critical, two High,
// one Medium, one Low, and one Finding with no severity at all.
func estate() []app.ReleaseSeverityRow {
	return []app.ReleaseSeverityRow{
		{CVE: "CVE-2026-0300", BaseScore: 55},  // Medium
		{CVE: "CVE-2026-0100", BaseScore: 100}, // Critical
		{CVE: "CVE-2026-0400", BaseScore: 12},  // Low
		{CVE: "CVE-2026-0201", BaseScore: 70},  // High (exactly on the boundary)
		{CVE: "CVE-2026-0101", BaseScore: 90},  // Critical (exactly on the boundary)
		{CVE: "CVE-2026-0200", BaseScore: 75},  // High
		{CVE: "CVE-2026-0500", BaseScore: 0},   // Unknown — NOT Low
	}
}

func jiraIntent() app.Intent {
	return app.Intent{
		ID: "int-1", Type: app.IntentJiraIssue, Destination: "themis-remediation",
		ReleaseID: "rel-1", ProjectID: "proj-1", ProductID: "prod-1",
		Snapshot: map[string]string{"release_id": "rel-1"},
		Lineage:  app.IntentLineage{EventType: "governance.finding_opened", EventID: "env-1"},
	}
}

// The RC-2 content rule: counts for all four buckets, CVE ids for Critical and High ONLY.
func TestRenderJiraIssueCountsAllSeveritiesAndListsCriticalAndHighOnly(t *testing.T) {
	src := &postureSource{rows: estate()}
	summary, body, err := serializer.NewOutwardRenderer(src).RenderJiraIssue(context.Background(), jiraIntent())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if want := "Themis remediation - Release rel-1"; summary != want {
		t.Errorf("summary = %q, want %q", summary, want)
	}
	if src.calls != 1 {
		t.Errorf("posture reads = %d, want 1 per ticket", src.calls)
	}
	got := string(body)

	for _, want := range []string{
		"Critical: 2", "High:     2", "Medium:   1", "Low:      1", "Unknown:  1",
		"Release:  rel-1", "Project:  proj-1", "Product:  prod-1", "Findings: 7",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("body is missing %q:\n%s", want, got)
		}
	}
	// Critical and High ids are listed.
	for _, want := range []string{"CVE-2026-0100", "CVE-2026-0101", "CVE-2026-0200", "CVE-2026-0201"} {
		if !strings.Contains(got, want) {
			t.Errorf("body is missing the %s id:\n%s", want, got)
		}
	}
	// Medium, Low and Unknown ids are NOT: that is the whole of the rule.
	for _, unwanted := range []string{"CVE-2026-0300", "CVE-2026-0400", "CVE-2026-0500"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("body lists %s, which is below High:\n%s", unwanted, got)
		}
	}
	if i, j := strings.Index(got, "CVE-2026-0100"), strings.Index(got, "CVE-2026-0101"); i > j {
		t.Error("the Critical ids are not sorted")
	}
	if i, j := strings.Index(got, "Severity counts"), strings.Index(got, "Critical (2)"); i > j {
		t.Error("the counts must precede the lists")
	}
}

// Rendering is deterministic: the same posture in a different order renders the same bytes. That
// is what makes a stored payload re-sendable and a retry provably the same communication.
func TestRenderJiraIssueIsDeterministic(t *testing.T) {
	first, _, err := serializer.NewOutwardRenderer(&postureSource{rows: estate()}).
		RenderJiraIssue(context.Background(), jiraIntent())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	shuffled := estate()
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].CVE > shuffled[j].CVE })
	second, _, err := serializer.NewOutwardRenderer(&postureSource{rows: shuffled}).
		RenderJiraIssue(context.Background(), jiraIntent())
	if err != nil {
		t.Fatalf("re-render: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("two renders of one posture differ:\n%s\n---\n%s", first, second)
	}
}

// A Release with nothing but mild Findings prints no Unknown line at all — the fifth bucket is
// reported only when it is real.
func TestRenderJiraIssueOmitsTheUnknownBucketWhenEmpty(t *testing.T) {
	_, body, err := serializer.NewOutwardRenderer(&postureSource{rows: []app.ReleaseSeverityRow{
		{CVE: "CVE-2026-0400", BaseScore: 12},
	}}).RenderJiraIssue(context.Background(), jiraIntent())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	got := string(body)
	if strings.Contains(got, "Unknown") {
		t.Errorf("an empty Unknown bucket must not be printed:\n%s", got)
	}
	if !strings.Contains(got, "Critical: 0") || !strings.Contains(got, "Low:      1") {
		t.Errorf("the four governed buckets are always printed:\n%s", got)
	}
	// With no Critical or High, no list section is emitted — and the rule is still stated.
	if strings.Contains(got, "Critical (") || strings.Contains(got, "High (") {
		t.Errorf("an empty severity must not get a list section:\n%s", got)
	}
}

// An unknown-severity Finding is counted, says so, and is never folded into Low.
func TestRenderJiraIssueExplainsTheUnknownBucket(t *testing.T) {
	_, body, err := serializer.NewOutwardRenderer(&postureSource{rows: []app.ReleaseSeverityRow{
		{CVE: "CVE-2026-0500"}, {CVE: "  "},
	}}).RenderJiraIssue(context.Background(), jiraIntent())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, "Unknown:  2") {
		t.Errorf("both unknown rows must be counted (a blank CVE is still a Finding):\n%s", got)
	}
	if !strings.Contains(got, "absence of evidence is not mildness") {
		t.Errorf("the Unknown bucket must explain itself:\n%s", got)
	}
}

// An empty posture still renders a ticket: zero counts are a statement about the Release, and a
// ticket saying "nothing open" is the right outcome of a clean evaluation.
func TestRenderJiraIssueOnAnEmptyPosture(t *testing.T) {
	_, body, err := serializer.NewOutwardRenderer(&postureSource{}).
		RenderJiraIssue(context.Background(), jiraIntent())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(string(body), "Findings: 0") {
		t.Errorf("body = %s", body)
	}
}

// The three refusals: no Release, no read seam, and a Governance read that failed. Each fails
// CLOSED — the service turns it into "no intent enqueued".
func TestRenderJiraIssueRefusals(t *testing.T) {
	ctx := context.Background()
	if _, _, err := serializer.NewOutwardRenderer(&postureSource{}).
		RenderJiraIssue(ctx, app.Intent{Type: app.IntentJiraIssue}); !errors.Is(err, app.ErrNoSubject) {
		t.Errorf("no release: err = %v, want ErrNoSubject", err)
	}
	if _, _, err := serializer.NewOutwardRenderer(nil).
		RenderJiraIssue(ctx, jiraIntent()); !errors.Is(err, serializer.ErrNoPostureReader) {
		t.Errorf("no reader: err = %v, want ErrNoPostureReader", err)
	}
	boom := errors.New("governance unreachable")
	if _, _, err := serializer.NewOutwardRenderer(&postureSource{err: boom}).
		RenderJiraIssue(ctx, jiraIntent()); !errors.Is(err, boom) {
		t.Errorf("read failure: err = %v, want the transport error", err)
	}
}

func TestRenderDecisionEmail(t *testing.T) {
	subject, body := serializer.RenderDecisionEmail(app.Intent{
		ID: "int-2", Type: app.IntentEmail, Destination: "security-decisions",
		FindingID: "fnd-1", ProposalID: "prop-1", ReleaseID: "rel-1",
		Snapshot: map[string]string{"cve": "CVE-2026-0100", "position_version": "2"},
		Lineage:  app.IntentLineage{EventType: "governance.proposal_accepted", EventID: "env-2"},
	})
	if want := "Themis decision - Finding fnd-1 (CVE-2026-0100)"; subject != want {
		t.Errorf("subject = %q, want %q", subject, want)
	}
	got := string(body)
	for _, want := range []string{
		"ACCEPTED", "Finding:          fnd-1", "Proposal:         prop-1", "Release:          rel-1",
		"CVE:              CVE-2026-0100", "Position version: 2",
		"Event:            governance.proposal_accepted (env-2)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("body is missing %q:\n%s", want, got)
		}
	}
}

// An absent fact is omitted, never printed blank: "Release:" with nothing after it reads as a
// claim that there is no Release, and the truth is that the event did not carry one.
func TestRenderDecisionEmailOmitsAbsentFacts(t *testing.T) {
	subject, body := serializer.RenderDecisionEmail(app.Intent{
		Type: app.IntentEmail, ProposalID: "prop-9", Snapshot: map[string]string{},
	})
	if want := "Themis decision - Finding prop-9"; subject != want {
		t.Errorf("subject = %q, want the proposal when there is no finding id", subject)
	}
	for _, unwanted := range []string{"Release:", "CVE:", "Position version:", "Event:", "Finding:"} {
		if strings.Contains(string(body), unwanted) {
			t.Errorf("body prints the absent %q:\n%s", unwanted, body)
		}
	}
}

func TestRenderOpsDeadLetterEmail(t *testing.T) {
	subject, body := serializer.RenderOpsDeadLetterEmail(app.Intent{
		ID: "int-3", Type: app.IntentEmail, Destination: "operations",
		Snapshot: map[string]string{
			"notification": "dead_letter", "dead_letter_intent_id": "int-1",
			"dead_letter_type": "jira_issue", "dead_letter_destination": "themis-remediation",
			"dead_letter_error": "jira: POST /rest/api/3/issue: status 503",
		},
	})
	if want := "Themis delivery gave up - intent int-1"; subject != want {
		t.Errorf("subject = %q, want %q", subject, want)
	}
	got := string(body)
	for _, want := range []string{
		"dead-lettered", "No Themis state changed", "Intent:      int-1",
		"Channel:     jira_issue", "Destination: themis-remediation", "status 503",
		"deliveryctl retry",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("body is missing %q:\n%s", want, got)
		}
	}
}

// RenderIntentPayload dispatches on the intent type and wraps each body in the payload envelope,
// so ONE stored byte slice carries both halves of what goes out.
func TestRenderIntentPayloadDispatches(t *testing.T) {
	r := serializer.NewOutwardRenderer(&postureSource{rows: estate()})
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		in      app.Intent
		subject string
	}{
		{"ticket", jiraIntent(), "Themis remediation - Release rel-1"},
		{
			"decision mail",
			app.Intent{Type: app.IntentEmail, FindingID: "fnd-1", Snapshot: map[string]string{}},
			"Themis decision - Finding fnd-1",
		},
		{
			"dead-letter mail",
			app.Intent{Type: app.IntentEmail, Snapshot: map[string]string{
				"notification": "dead_letter", "dead_letter_intent_id": "int-1",
			}},
			"Themis delivery gave up - intent int-1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := r.RenderIntentPayload(ctx, tc.in)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			subject, body := app.SplitPayload(payload)
			if subject != tc.subject {
				t.Errorf("subject = %q, want %q", subject, tc.subject)
			}
			if len(body) == 0 {
				t.Error("empty body")
			}
		})
	}

	// A type with no renderer is an error, not an empty payload: the service fails closed on it.
	if _, err := r.RenderIntentPayload(ctx, app.Intent{Type: "ci_build"}); err == nil {
		t.Error("an unknown intent type must be refused")
	}
}
