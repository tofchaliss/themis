package serializer

// outward.go renders the OUTWARD-DELIVERY payloads (N-M1b): the remediation ticket body and the
// two notification mails. It sits beside the standards serializers because it is the same kind of
// thing — an abstract record rendered deterministically into bytes — but the audience is a person
// reading a ticket or a mail, not a VEX consumer, so the formats are plain text and no standard
// governs them.
//
// Three rules hold the whole file together:
//
//  1. DETERMINISTIC. The same intent plus the same posture renders the same bytes: counts before
//     lists, lists sorted, nothing timestamped at render time. The payload is snapshotted at
//     enqueue and re-sent on every retry, so a render that varied would make "the same snapshot
//     was delivered" unverifiable.
//  2. FACTS ONLY. Counts, CVE ids, identities and the error that exhausted a delivery. No model
//     output, no credential, no workspace content ever reaches an outward channel (RC-7).
//  3. SEVERITY IS A COUNT, A CVE ID IS A LIST — and only for Critical and High (RC-2). Listing
//     every id at every severity is what makes a ticket unreadable at estate scale.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// ErrNoPostureReader is returned when a remediation ticket is rendered without the Governance
// read seam it needs. It fails closed: a ticket with no counts is not a smaller ticket, it is a
// ticket that says nothing about the Release it names.
var ErrNoPostureReader = errors.New("communication: no release-posture reader for the remediation ticket")

// The four governed severity buckets of RC-2, plus the honest fifth.
const (
	sevCritical = "Critical"
	sevHigh     = "High"
	sevMedium   = "Medium"
	sevLow      = "Low"
	// sevUnknown is NOT one of RC-2's buckets and is reported only when it is non-empty. A
	// Finding whose card carries no severity and no exploitation signal must not be counted as
	// Low — that would be a claim, and the absence of evidence is not evidence of mildness.
	sevUnknown = "Unknown"
)

// severityOrder is the order the counts print in (worst first), and the order the CVE lists
// follow. It is a fixed slice rather than a map iteration because the output is compared
// byte-for-byte across retries.
var severityOrder = []string{sevCritical, sevHigh, sevMedium, sevLow, sevUnknown}

// listedSeverities are the buckets whose CVE ids are listed (RC-2). Medium, Low and Unknown are
// counts with no list.
var listedSeverities = []string{sevCritical, sevHigh}

// OutwardRenderer renders an outward delivery intent's payload. It implements
// app.IntentPayloadRenderer, and the app's DeliveryIntentService calls it ONCE per intent, at
// enqueue time (D-N-3).
type OutwardRenderer struct {
	posture app.ReleaseSeverityReader
	// identity resolves a release to its product, project and version through the Registry
	// (owner ask 2026-10-21: a mail that says three UUIDs means nothing to its reader). Nil, or
	// a failed read, leaves the ids in place: a name is a courtesy, an unsent ticket is not.
	identity app.ReleaseIdentityReader
	// dashboard is the base URL a webhook's link points into (D4); empty = no link.
	dashboard string
}

// WithIdentity attaches the Registry name chain.
func (r OutwardRenderer) WithIdentity(id app.ReleaseIdentityReader) OutwardRenderer {
	r.identity = id
	return r
}

// releaseLabel names a release for a subject line — "Product / Project v1.2" when the chain
// resolves, the bare release id otherwise — and the facts that go with it.
func (r OutwardRenderer) releaseLabel(ctx context.Context, in app.Intent) (label string, facts []fact) {
	label = "Release " + in.ReleaseID
	facts = []fact{{"Release", in.ReleaseID}, {"Project", in.ProjectID}, {"Product", in.ProductID}}
	if r.identity == nil || strings.TrimSpace(in.ReleaseID) == "" {
		return label, facts
	}
	ref, err := r.identity.ReleaseIdentity(ctx, in.ReleaseID)
	if err != nil {
		return label, facts
	}
	label = ref.Product + " / " + ref.Project + " v" + ref.Version
	facts = []fact{
		{"Product", ref.Product + " (" + firstNonEmpty(in.ProductID, "id unknown") + ")"},
		{"Project", ref.Project + " (" + firstNonEmpty(in.ProjectID, "id unknown") + ")"},
		{"Release", "v" + ref.Version + " (" + in.ReleaseID + ")"},
	}
	return label, facts
}

// Compile-time proof that the renderer satisfies the app port it exists for.
var _ app.IntentPayloadRenderer = OutwardRenderer{}

// NewOutwardRenderer builds the renderer over Governance's release-posture read seam. A nil
// reader leaves mail rendering working (it needs no read) and makes ticket rendering refuse.
func NewOutwardRenderer(posture app.ReleaseSeverityReader) OutwardRenderer {
	return OutwardRenderer{posture: posture}
}

// RenderIntentPayload renders the payload envelope (subject + body) for one intent, dispatching
// on its type — and, for mail, on whether it exists because another intent died.
func (r OutwardRenderer) RenderIntentPayload(ctx context.Context, in app.Intent) ([]byte, error) {
	switch {
	case in.Type == app.IntentJiraIssue:
		summary, description, err := r.RenderJiraIssue(ctx, in)
		if err != nil {
			return nil, err
		}
		return app.BuildPayload(summary, description), nil
	case in.Type == app.IntentEmail && in.IsDeadLetterNotification():
		subject, body := RenderOpsDeadLetterEmail(in)
		return app.BuildPayload(subject, body), nil
	case in.Type == app.IntentEmail && in.IsEvaluationNotification():
		subject, body, err := r.RenderEvaluationEmail(ctx, in)
		if err != nil {
			return nil, err
		}
		return app.BuildPayload(subject, body), nil
	case in.Type == app.IntentEmail:
		subject, body := RenderDecisionEmail(in)
		return app.BuildPayload(subject, body), nil
	case in.Type == app.IntentCIRebuild:
		subject, body := r.renderCIRebuild(ctx, in)
		return app.BuildPayload(subject, body), nil
	case in.Type == app.IntentWebhook:
		summary, body, err := r.RenderWebhook(ctx, in)
		if err != nil {
			return nil, err
		}
		return app.BuildPayload(summary, body), nil
	default:
		return nil, fmt.Errorf("communication: no outward renderer for intent type %q", in.Type)
	}
}

// jiraSummary is the ticket's summary line. One ticket per Release is kept by the ticket INDEX
// and the label, never by this text, so the summary may carry the names a reader wants
// ("Product / Project v1.2") and fall back to the release id when the chain is unavailable;
// a later update rewrites it in full (M1b-4).
func jiraSummary(label string) string {
	return "Themis remediation - " + label
}

// RenderJiraIssue renders the remediation ticket for the intent's Release: severity counts for
// all four buckets, CVE ids for Critical and High only (RC-2).
func (r OutwardRenderer) RenderJiraIssue(ctx context.Context, in app.Intent) (string, []byte, error) {
	if strings.TrimSpace(in.ReleaseID) == "" {
		return "", nil, app.ErrNoSubject
	}
	if r.posture == nil {
		return "", nil, ErrNoPostureReader
	}
	rows, err := r.posture.ReleaseSeverity(ctx, in.ReleaseID)
	if err != nil {
		return "", nil, err
	}

	counts, cves := bucket(rows)
	label, who := r.releaseLabel(ctx, in)
	var b strings.Builder
	b.WriteString("Themis tracks remediation of this Release. One ticket per Release: the unit a\n")
	b.WriteString("rebuild addresses is a Release, so the unit a tracking ticket addresses is a Release.\n\n")
	writeFacts(&b, append(who, fact{"Findings", fmt.Sprintf("%d", len(rows))}))

	b.WriteString("\nSeverity counts\n")
	for _, sev := range severityOrder {
		if sev == sevUnknown && counts[sev] == 0 {
			continue // not one of the governed buckets; shown only when it is real
		}
		fmt.Fprintf(&b, "  %-9s %d\n", sev+":", counts[sev])
	}

	for _, sev := range listedSeverities {
		if counts[sev] == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s (%d)\n", sev, counts[sev])
		for _, cve := range cves[sev] {
			b.WriteString("  " + cve + "\n")
		}
	}

	b.WriteString("\nMedium and Low are reported as counts only: listing every CVE id at every severity\n")
	b.WriteString("makes a ticket unreadable at estate scale.\n")
	if counts[sevUnknown] > 0 {
		b.WriteString("\nUnknown means no severity could be read for those Findings. They are reported\n")
		b.WriteString("separately rather than counted as Low: absence of evidence is not mildness.\n")
	}
	writeUploadOutcomeSection(&b, in)
	writeRebuildSection(&b, in)
	b.WriteString("\nThis ticket is a PROJECTION of Themis state. No Themis decision follows from a Jira\n")
	b.WriteString("transition, and resolving a Finding stays a decision taken in Themis by a person.\n")

	return jiraSummary(label), []byte(b.String()), nil
}

// RenderEvaluationEmail renders the mail that follows a Release evaluation (M2-8 step 4 / N-M2f):
// the same posture the ticket states — counts for all four buckets, CVE ids for Critical and
// High — told to the governed audience. It reads the posture like the ticket does, so the two
// cannot disagree about what the Release contains. The ticket, not the mail, is the tracking
// surface: the mail says where to look.
func (r OutwardRenderer) RenderEvaluationEmail(ctx context.Context, in app.Intent) (string, []byte, error) {
	if strings.TrimSpace(in.ReleaseID) == "" {
		return "", nil, app.ErrNoSubject
	}
	if r.posture == nil {
		return "", nil, ErrNoPostureReader
	}
	rows, err := r.posture.ReleaseSeverity(ctx, in.ReleaseID)
	if err != nil {
		return "", nil, err
	}
	counts, cves := bucket(rows)
	label, who := r.releaseLabel(ctx, in)
	subject := fmt.Sprintf("Themis evaluated %s - Critical %d, High %d", label, counts[sevCritical], counts[sevHigh])

	var b strings.Builder
	b.WriteString("Themis has evaluated a new SBOM for this Release. This is the Release's posture as it\n")
	b.WriteString("stands now; the remediation ticket for the Release carries the same figures.\n\n")
	writeFacts(&b, append(who,
		fact{"SBOM", in.Snapshot["sbom_id"]},
		fact{"Findings", fmt.Sprintf("%d", len(rows))},
		fact{"Event", eventFact(in)},
	))
	b.WriteString("\nSeverity counts\n")
	for _, sev := range severityOrder {
		if sev == sevUnknown && counts[sev] == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-9s %d\n", sev+":", counts[sev])
	}
	for _, sev := range listedSeverities {
		if counts[sev] == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s (%d)\n", sev, counts[sev])
		for _, cve := range cves[sev] {
			b.WriteString("  " + cve + "\n")
		}
	}
	writeUploadOutcomeSection(&b, in)
	writeRebuildSection(&b, in)
	b.WriteString("\nNo Themis decision follows from this mail. The authoritative record is Themis; this\n")
	b.WriteString("mail carries no attachment and no model output.\n")
	return subject, []byte(b.String()), nil
}

// writeUploadOutcomeSection states what this SBOM changed against the one filed before it
// (EDR-REMEDIATION-01 D3), when the evaluation carried an outcome. It is a report: the wording
// says plainly that a Finding no longer present is still open, because a reader skimming
// "3 no longer present" would otherwise take them as closed.
func writeUploadOutcomeSection(b *strings.Builder, in app.Intent) {
	if _, ok := in.Snapshot[app.SnapshotOutcomeNew]; !ok {
		return
	}
	b.WriteString("\nWhat this SBOM changed\n")
	if in.Snapshot[app.SnapshotOutcomeHasBaseline] != "true" {
		b.WriteString("  This is the Release's first SBOM, so every Finding present is new.\n")
	}
	writeFacts(b, []fact{
		{"New", withCVEs(in.Snapshot[app.SnapshotOutcomeNew], in.Snapshot[app.SnapshotOutcomeNewCVEs])},
		{"Reappeared", withCVEs(in.Snapshot[app.SnapshotOutcomeReappeared], in.Snapshot[app.SnapshotOutcomeReappearedCVEs])},
		{"No longer present", withCVEs(in.Snapshot[app.SnapshotOutcomeNoLongerPresent], in.Snapshot[app.SnapshotOutcomeGoneCVEs])},
		{"Unchanged", in.Snapshot[app.SnapshotOutcomeUnchanged]},
		{"Not judged", in.Snapshot[app.SnapshotOutcomeNotJudged]},
	})
	b.WriteString("  A Finding no longer present in this build is still open, with its decision, until a person resolves it.\n")
}

// withCVEs is "3 (CVE-1, CVE-2, CVE-3)", or the bare count when there is no list.
func withCVEs(count, cves string) string {
	if cves == "" {
		return count
	}
	return count + " (" + strings.ReplaceAll(cves, ",", ", ") + ")"
}

// writeRebuildSection states the rebuild loop's decision for this evaluation (M2-8 / N-M2i) when
// the intent carries one: what the cycle targets, what this rebuild closed, what is still open,
// and whether the loop goes on, succeeded, or gave up — in which case it says so plainly, because
// exhaustion is the one outcome that needs a person (M2-8). A clean evaluation carries no section.
func writeRebuildSection(b *strings.Builder, in app.Intent) {
	state := in.Snapshot[app.SnapshotRebuildState]
	if state == "" {
		return
	}
	attempt, limit := in.Snapshot[app.SnapshotRebuildAttempt], in.Snapshot[app.SnapshotRebuildMaxAttempts]
	b.WriteString("\nRebuild loop\n")
	switch state {
	case app.OutcomeOpened:
		fmt.Fprintf(b, "  Opened: Critical and High Findings remain, so Themis asked the build system for a rebuild (attempt %s of %s).\n", attempt, limit)
	case app.OutcomeContinuing:
		fmt.Fprintf(b, "  Continuing: the last rebuild left targeted Findings open, so Themis asked for another (attempt %s of %s).\n", attempt, limit)
	case app.OutcomeSucceeded:
		b.WriteString("  Succeeded: every Finding this cycle targeted is closed. No further rebuild is asked for.\n")
	case app.OutcomeExhausted:
		fmt.Fprintf(b, "  ATTEMPTS EXHAUSTED (%s of %s): targeted Findings are still open and Themis will not ask for another rebuild in this cycle. A person decides what happens next.\n", attempt, limit)
	default:
		fmt.Fprintf(b, "  %s\n", state)
	}
	writeFacts(b, []fact{
		{"Targeted", in.Snapshot[app.SnapshotRebuildTargeted]},
		{"Closed", in.Snapshot[app.SnapshotRebuildClosed]},
		{"Still open", in.Snapshot[app.SnapshotRebuildOpen]},
		{"Compared against", in.Snapshot[app.SnapshotRebuildBaseline]},
	})
	b.WriteString("  Findings are never auto-resolved by a rebuild; a closed Finding is one the new SBOM no longer opens.\n")
}

// RenderCIRebuild renders the rebuild instruction as text (M2-6 / N-M2g): the parameters the
// build job receives, as the operator will read them on the intent. The Jenkins sender takes the
// parameters from the snapshot, not from this text; the text exists so a rebuild intent is as
// inspectable as a ticket or a mail, and so the content-address rule (D-N-3) covers it too.
func RenderCIRebuild(in app.Intent) (string, []byte) {
	return OutwardRenderer{}.renderCIRebuild(context.Background(), in)
}

func (r OutwardRenderer) renderCIRebuild(ctx context.Context, in app.Intent) (string, []byte) {
	label, who := r.releaseLabel(ctx, in)
	subject := "Themis rebuild - " + label + " - attempt " + firstNonEmpty(in.Snapshot[app.SnapshotAttempt], "1")
	var b strings.Builder
	b.WriteString("Themis asks the build system to rebuild this Release so the targeted Findings can be\n")
	b.WriteString("re-evaluated from a new SBOM. The job uploads the new SBOM and calls Themis back; the\n")
	b.WriteString("callback changes no Finding - only the evaluation of the new SBOM can (M2-7).\n\n")
	writeFacts(&b, append([]fact{{"Job", in.Destination}}, append(who, []fact{
		{"Prior SBOM", in.Snapshot[app.SnapshotPriorSBOMID]},
		{"Targeted", in.Snapshot[app.SnapshotTargetedCVEs]},
		{"Attempt", in.Snapshot[app.SnapshotAttempt]},
		{"Event", eventFact(in)},
	}...)...))
	return subject, []byte(b.String())
}

// RenderDecisionEmail renders the notification for an accepted proposal (RC-5): the immutable
// facts recorded when the decision was taken, and nothing else.
func RenderDecisionEmail(in app.Intent) (string, []byte) {
	subject := "Themis decision - Finding " + firstNonEmpty(in.FindingID, in.ProposalID)
	if cve := in.Snapshot["cve"]; cve != "" {
		subject += " (" + cve + ")"
	}

	var b strings.Builder
	b.WriteString("A proposal about this Finding was ACCEPTED, so an Enterprise Position is now of\n")
	b.WriteString("record in Themis.\n\n")
	writeFacts(&b, []fact{
		{"Finding", in.FindingID},
		{"Proposal", in.ProposalID},
		{"Release", in.ReleaseID},
		{"CVE", in.Snapshot["cve"]},
		{"Position version", in.Snapshot["position_version"]},
		{"Event", eventFact(in)},
	})
	b.WriteString("\nThese are the facts as they stood when the decision was taken. The authoritative\n")
	b.WriteString("record is Themis; this mail carries no attachment and no model output.\n")
	return subject, []byte(b.String())
}

// RenderOpsDeadLetterEmail renders the operations notification for a delivery that gave up. It
// says what died and what a person can do about it — and says plainly that nothing in Themis
// moved, because the one thing an operator must not infer from a failed delivery is a changed
// security position (RC-7).
func RenderOpsDeadLetterEmail(in app.Intent) (string, []byte) {
	dead := in.Snapshot["dead_letter_intent_id"]
	subject := "Themis delivery gave up - intent " + dead

	var b strings.Builder
	b.WriteString("An outward delivery exhausted its attempts and was dead-lettered.\n\n")
	b.WriteString("No Themis state changed. A Finding, a Position and a Release are untouched by a\n")
	b.WriteString("delivery failure: outward availability is never a security-truth change.\n\n")
	writeFacts(&b, []fact{
		{"Intent", dead},
		{"Channel", in.Snapshot["dead_letter_type"]},
		{"Destination", in.Snapshot["dead_letter_destination"]},
		{"Last error", in.Snapshot["dead_letter_error"]},
		{"Event", eventFact(in)},
	})
	b.WriteString("\nOperator: `deliveryctl list-deadletters` to see it, `deliveryctl retry <id>` to try\n")
	b.WriteString("again once the cause is fixed, `deliveryctl cancel <id>` to drop it.\n")
	return subject, []byte(b.String())
}

// bucket counts the posture rows per severity and collects the CVE ids per severity, sorted and
// deduplicated. Sorting is what makes two renders of one posture byte-identical whatever order
// Governance returned the rows in.
func bucket(rows []app.ReleaseSeverityRow) (map[string]int, map[string][]string) {
	counts := map[string]int{}
	seen := map[string]map[string]bool{}
	for _, row := range rows {
		sev := severityOf(row.BaseScore)
		counts[sev]++
		cve := strings.TrimSpace(row.CVE)
		if cve == "" {
			continue
		}
		if seen[sev] == nil {
			seen[sev] = map[string]bool{}
		}
		seen[sev][cve] = true
	}
	cves := map[string][]string{}
	for sev, set := range seen {
		for cve := range set {
			cves[sev] = append(cves[sev], cve)
		}
		sort.Strings(cves[sev])
	}
	return counts, cves
}

// severityOf reads a severity bucket off Governance's base_score.
//
// The posture projection carries no severity WORD — it carries `base_score`, Knowledge's
// CVE-intrinsic composite (0–100), and `band`, which is EXPLOITABILITY and a different question.
// RC-2's four buckets therefore come from the score, against the same baseline ladder Knowledge
// built it from: Critical 90, High 70, Medium 40, Low 10. Inverting that ladder is the closest
// honest reconstruction available without a second read per Finding.
//
// Two consequences, stated rather than hidden. A card lifted by EPSS or KEV can cross into the
// bucket above its intrinsic severity — which is the right answer for a ticket about what to fix
// first, and the wrong answer if the ticket is read as a CVSS report. And a score of 0 is
// `Unknown`, never `Low`: nothing was known about that card's severity, which is not the same as
// knowing it is mild.
func severityOf(baseScore int) string {
	switch {
	case baseScore >= domain.SeverityCriticalFloor:
		return sevCritical
	case baseScore >= domain.SeverityHighFloor:
		return sevHigh
	case baseScore >= domain.SeverityMediumFloor:
		return sevMedium
	case baseScore > 0:
		return sevLow
	default:
		return sevUnknown
	}
}

// fact is one "Label: value" line of an outward body.
type fact struct{ label, value string }

// writeFacts prints the facts that have a value, label-aligned. An absent fact is OMITTED rather
// than printed empty: a blank line next to "Product:" reads as "no product", and the truth is
// that the originating event did not carry one.
func writeFacts(b *strings.Builder, facts []fact) {
	width := 0
	for _, f := range facts {
		if f.value != "" && len(f.label) > width {
			width = len(f.label)
		}
	}
	for _, f := range facts {
		if f.value == "" {
			continue
		}
		fmt.Fprintf(b, "%-*s %s\n", width+1, f.label+":", f.value)
	}
}

// eventFact renders the originating event as one traceable line: an outward effect must always
// be answerable for the fact that caused it.
func eventFact(in app.Intent) string {
	if in.Lineage.EventType == "" {
		return ""
	}
	out := in.Lineage.EventType
	if in.Lineage.EventID != "" {
		out += " (" + in.Lineage.EventID + ")"
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
