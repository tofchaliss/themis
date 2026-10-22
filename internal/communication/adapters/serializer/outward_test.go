package serializer_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
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
// N-M2f: the evaluation mail states the same posture the ticket does — counts for every bucket,
// ids for Critical and High only — and refuses without a Release or a posture reader.
func TestRenderEvaluationEmail(t *testing.T) {
	r := serializer.NewOutwardRenderer(&postureSource{rows: estate()})
	in := app.Intent{Type: app.IntentEmail, ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "prj-1",
		Snapshot: map[string]string{"notification": "release_evaluated", "sbom_id": "ev-9"},
		Lineage:  app.IntentLineage{EventType: "governance.release_evaluated", EventID: "env-1"}}
	subject, body, err := r.RenderEvaluationEmail(context.Background(), in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.HasPrefix(subject, "Themis evaluated Release rel-1 - Critical ") {
		t.Errorf("subject = %q", subject)
	}
	text := string(body)
	for _, want := range []string{"Release", "rel-1", "SBOM", "ev-9", "Critical:", "High:", "Medium:", "Low:", "No Themis decision follows"} {
		if !strings.Contains(text, want) {
			t.Errorf("body lacks %q:\n%s", want, text)
		}
	}
	// The same bucketing as the ticket: whatever the ticket lists, the mail lists.
	_, ticket, err := r.RenderJiraIssue(context.Background(), app.Intent{Type: app.IntentJiraIssue, ReleaseID: "rel-1"})
	if err != nil {
		t.Fatalf("ticket: %v", err)
	}
	for _, line := range strings.Split(string(ticket), "\n") {
		if strings.HasPrefix(line, "  CVE-") && !strings.Contains(text, line) {
			t.Errorf("ticket lists %q, the mail does not", strings.TrimSpace(line))
		}
	}
	if _, _, err := r.RenderEvaluationEmail(context.Background(), app.Intent{Type: app.IntentEmail}); err == nil {
		t.Error("no Release must be refused")
	}
	if _, _, err := serializer.NewOutwardRenderer(nil).RenderEvaluationEmail(context.Background(), in); err == nil {
		t.Error("no posture reader must be refused")
	}
	if _, _, err := serializer.NewOutwardRenderer(&postureSource{err: errors.New("governance down")}).RenderEvaluationEmail(context.Background(), in); err == nil {
		t.Error("a failed posture read must surface")
	}
}

// N-M2g: the rebuild intent is rendered as text an operator can read — the job, the identity,
// the prior SBOM, the targeted set and the attempt — and nothing a job would not be handed.
func TestRenderCIRebuild(t *testing.T) {
	subject, body := serializer.RenderCIRebuild(app.Intent{Type: app.IntentCIRebuild, ReleaseID: "rel-1", ProductID: "prod-1",
		ProjectID: "prj-1", Destination: "team/build-image",
		Snapshot: map[string]string{"attempt": "1", "targeted_cves": "CVE-2026-1,CVE-2026-2", "prior_sbom_id": "ev-1"}})
	if subject != "Themis rebuild - Release rel-1 - attempt 1" {
		t.Errorf("subject = %q", subject)
	}
	for _, want := range []string{"team/build-image", "rel-1", "prod-1", "prj-1", "ev-1", "CVE-2026-1,CVE-2026-2", "changes no Finding"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if s, _ := serializer.RenderCIRebuild(app.Intent{Type: app.IntentCIRebuild, ReleaseID: "rel-2", Snapshot: map[string]string{}}); !strings.HasSuffix(s, "attempt 1") {
		t.Errorf("a missing attempt reads as the first: %q", s)
	}
}

// N-M2i: the loop's decision is a section on the ticket and on the evaluation mail — each state in
// its own words — and absent when the evaluation carried none.
func TestRebuildSectionOnTicketAndMail(t *testing.T) {
	r := serializer.NewOutwardRenderer(&postureSource{rows: estate()})
	ctx := context.Background()
	base := map[string]string{"rebuild_attempt": "2", "rebuild_max_attempts": "2", "rebuild_targeted": "CVE-2026-0100,CVE-2026-0101",
		"rebuild_closed": "CVE-2026-0101", "rebuild_open": "CVE-2026-0100", "rebuild_baseline_sbom": "ev-2"}
	for state, want := range map[string]string{
		"opened":     "Opened: Critical and High Findings remain",
		"continuing": "Continuing: the last rebuild left targeted Findings open",
		"succeeded":  "Succeeded: every Finding this cycle targeted is closed",
		"exhausted":  "ATTEMPTS EXHAUSTED (2 of 2)",
		"odd":        "  odd",
	} {
		snap := map[string]string{"rebuild_state": state}
		for k, v := range base {
			snap[k] = v
		}
		ticket := app.Intent{Type: app.IntentJiraIssue, ReleaseID: "rel-1", Snapshot: snap}
		_, body, err := r.RenderJiraIssue(ctx, ticket)
		if err != nil {
			t.Fatalf("%s ticket: %v", state, err)
		}
		mailIn := app.Intent{Type: app.IntentEmail, ReleaseID: "rel-1", Snapshot: snap}
		mailIn.Snapshot["notification"] = "release_evaluated"
		_, mail, err := r.RenderEvaluationEmail(ctx, mailIn)
		if err != nil {
			t.Fatalf("%s mail: %v", state, err)
		}
		for _, text := range []string{string(body), string(mail)} {
			for _, w := range []string{"Rebuild loop", want, "Still open", "CVE-2026-0100", "Compared against", "ev-2", "never auto-resolved"} {
				if !strings.Contains(text, w) {
					t.Errorf("%s lacks %q:\n%s", state, w, text)
				}
			}
		}
	}
	_, body, err := r.RenderJiraIssue(ctx, app.Intent{Type: app.IntentJiraIssue, ReleaseID: "rel-1"})
	if err != nil || strings.Contains(string(body), "Rebuild loop") {
		t.Errorf("a ticket without a loop decision must carry no section (err %v)", err)
	}
}

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
			"evaluation mail",
			app.Intent{Type: app.IntentEmail, ReleaseID: "rel-1", Snapshot: map[string]string{"notification": "release_evaluated"}},
			"Themis evaluated Release rel-1 - Critical 2, High 2",
		},
		{
			"rebuild",
			app.Intent{Type: app.IntentCIRebuild, ReleaseID: "rel-1", Destination: "team/build-image",
				Snapshot: map[string]string{"attempt": "2", "targeted_cves": "CVE-2026-1", "prior_sbom_id": "ev-1"}},
			"Themis rebuild - Release rel-1 - attempt 2",
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

// --- names, not ids (owner ask 2026-10-21) --------------------------------------------------

type identitySource struct {
	ref domain.RollupProductRef
	err error
}

func (s identitySource) ReleaseIdentity(context.Context, string) (domain.RollupProductRef, error) {
	return s.ref, s.err
}

// With the Registry chain wired, the ticket, the evaluation mail and the rebuild instruction say
// "Product / Project vVersion" in their subject and carry the names in the body with the ids
// beside them; without the chain, or when it fails, the ids stand alone exactly as before.
func TestOutwardRenderersNameTheRelease(t *testing.T) {
	ctx := context.Background()
	named := serializer.NewOutwardRenderer(&postureSource{rows: estate()}).
		WithIdentity(identitySource{ref: domain.RollupProductRef{Product: "smallbox", Project: "demo", Version: "1.1.0", ReleaseID: "rel-1"}})
	in := app.Intent{Type: app.IntentJiraIssue, ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "prj-1", Snapshot: map[string]string{}}

	summary, body, err := named.RenderJiraIssue(ctx, in)
	if err != nil {
		t.Fatalf("ticket: %v", err)
	}
	if summary != "Themis remediation - smallbox / demo v1.1.0" {
		t.Errorf("summary = %q", summary)
	}
	for _, want := range []string{"smallbox (prod-1)", "demo (prj-1)", "v1.1.0 (rel-1)"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("ticket body lacks %q:\n%s", want, body)
		}
	}
	mail := in
	mail.Type, mail.Snapshot = app.IntentEmail, map[string]string{"notification": "release_evaluated"}
	subject, mbody, err := named.RenderEvaluationEmail(ctx, mail)
	if err != nil {
		t.Fatalf("mail: %v", err)
	}
	if !strings.HasPrefix(subject, "Themis evaluated smallbox / demo v1.1.0 - Critical ") || !strings.Contains(string(mbody), "smallbox (prod-1)") {
		t.Errorf("mail = %q / %s", subject, mbody)
	}
	rebuild := in
	rebuild.Type, rebuild.Snapshot = app.IntentCIRebuild, map[string]string{"attempt": "1"}
	payload, err := named.RenderIntentPayload(ctx, rebuild)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rs, rb := app.SplitPayload(payload); rs != "Themis rebuild - smallbox / demo v1.1.0 - attempt 1" || !strings.Contains(string(rb), "demo (prj-1)") {
		t.Errorf("rebuild = %q / %s", rs, rb)
	}

	// The chain failing, or absent, leaves the ids: a name is a courtesy, an unsent ticket is not.
	failing := serializer.NewOutwardRenderer(&postureSource{rows: estate()}).WithIdentity(identitySource{err: errors.New("registry down")})
	if s, b, err := failing.RenderJiraIssue(ctx, in); err != nil || s != "Themis remediation - Release rel-1" || !strings.Contains(string(b), "Release:") {
		t.Errorf("failing chain: %q %v", s, err)
	}
	if s, _, err := serializer.NewOutwardRenderer(&postureSource{rows: estate()}).RenderJiraIssue(ctx, in); err != nil || s != "Themis remediation - Release rel-1" {
		t.Errorf("no chain: %q %v", s, err)
	}
	// Ids the event never carried read as unknown rather than as an empty bracket.
	bare := app.Intent{Type: app.IntentJiraIssue, ReleaseID: "rel-1", Snapshot: map[string]string{}}
	if _, b, err := named.RenderJiraIssue(ctx, bare); err != nil || !strings.Contains(string(b), "smallbox (id unknown)") {
		t.Errorf("bare ids: %v\n%s", err, b)
	}
}

// EDR-REMEDIATION-01 D3: the ticket and the mail state what the SBOM changed when the event
// carried it, say plainly that "no longer present" is still open, and say nothing otherwise.
func TestRenderUploadOutcomeSection(t *testing.T) {
	r := serializer.NewOutwardRenderer(&postureSource{rows: estate()})
	snap := map[string]string{"notification": "release_evaluated", "sbom_id": "ev-9",
		app.SnapshotOutcomeNew: "1", app.SnapshotOutcomeReappeared: "0", app.SnapshotOutcomeNoLongerPresent: "2",
		app.SnapshotOutcomeUnchanged: "5", app.SnapshotOutcomeNotJudged: "0", app.SnapshotOutcomeNewCVEs: "CVE-2026-1",
		app.SnapshotOutcomeGoneCVEs: "CVE-2025-1,CVE-2025-2", app.SnapshotOutcomeHasBaseline: "true"}
	_, mail, err := r.RenderEvaluationEmail(context.Background(), app.Intent{Type: app.IntentEmail, ReleaseID: "rel-1", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	_, ticket, err := r.RenderJiraIssue(context.Background(), app.Intent{Type: app.IntentJiraIssue, ReleaseID: "rel-1", Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"mail": string(mail), "ticket": string(ticket)} {
		for _, want := range []string{"What this SBOM changed", "New:", "1 (CVE-2026-1)", "No longer present:", "2 (CVE-2025-1, CVE-2025-2)",
			"Unchanged:", "still open, with its decision"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, text)
			}
		}
		if strings.Contains(text, "first SBOM") {
			t.Errorf("%s calls a release with a baseline its first SBOM", name)
		}
	}
	snap[app.SnapshotOutcomeHasBaseline] = "false"
	_, first, _ := r.RenderEvaluationEmail(context.Background(), app.Intent{Type: app.IntentEmail, ReleaseID: "rel-1", Snapshot: snap})
	if !strings.Contains(string(first), "first SBOM") {
		t.Errorf("first-SBOM wording missing:\n%s", first)
	}
	_, none, _ := r.RenderJiraIssue(context.Background(), app.Intent{Type: app.IntentJiraIssue, ReleaseID: "rel-1"})
	if strings.Contains(string(none), "What this SBOM changed") {
		t.Error("an intent without an outcome rendered the section")
	}
}
