package serializer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/themis-project/themis/internal/communication/app"
)

// The webhook payload (EDR-REMEDIATION-01 D4): a small, STABLE Themis document rather than the
// raw event, so no internal field becomes a public contract by accident. `text` carries the same
// summary as a plain string so a Slack or Teams incoming webhook renders it without a relay.
//
// Field set, frozen: event, product, project, release, release_id, finding_id, summary, link,
// text. Empty fields are omitted.

// WebhookDocument is the JSON body a webhook receiver gets.
type WebhookDocument struct {
	Event     string `json:"event"`
	Product   string `json:"product,omitempty"`
	Project   string `json:"project,omitempty"`
	Release   string `json:"release,omitempty"`
	ReleaseID string `json:"release_id,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
	Summary   string `json:"summary"`
	Link      string `json:"link,omitempty"`
	Text      string `json:"text"`
}

const (
	webhookSummaryCVELimit  = 20
	webhookDefaultEventName = "themis"
)

// WithDashboardURL sets the base URL a webhook's `link` points into (the dashboard's release
// page). Empty leaves `link` out.
func (r OutwardRenderer) WithDashboardURL(base string) OutwardRenderer {
	r.dashboard = strings.TrimRight(strings.TrimSpace(base), "/")
	return r
}

func (r OutwardRenderer) releaseLink(releaseID string) string {
	if r.dashboard == "" || releaseID == "" {
		return ""
	}
	return r.dashboard + "/#/release/" + url.PathEscape(releaseID)
}

// RenderWebhook renders the summary line and the JSON document for one webhook intent.
func (r OutwardRenderer) RenderWebhook(ctx context.Context, in app.Intent) (string, []byte, error) {
	kind := firstNonEmpty(in.Snapshot[app.SnapshotWebhookEvent], webhookDefaultEventName)
	doc := WebhookDocument{Event: kind, ReleaseID: in.ReleaseID, FindingID: in.FindingID, Link: r.releaseLink(in.ReleaseID)}
	label := ""
	if in.ReleaseID != "" {
		label, _ = r.releaseLabel(ctx, in)
		if r.identity != nil {
			if ref, err := r.identity.ReleaseIdentity(ctx, in.ReleaseID); err == nil {
				doc.Product, doc.Project, doc.Release = ref.Product, ref.Project, ref.Version
			}
		}
	}
	s := in.Snapshot
	switch kind {
	case app.WebhookReleaseEvaluated:
		summary := "Themis evaluated " + label
		if r.posture != nil {
			if rows, err := r.posture.ReleaseSeverity(ctx, in.ReleaseID); err == nil {
				counts, _ := bucket(rows)
				summary += fmt.Sprintf(": Critical %d, High %d, Medium %d, Low %d", counts[sevCritical], counts[sevHigh], counts[sevMedium], counts[sevLow])
			}
		}
		if _, ok := s[app.SnapshotOutcomeNew]; ok {
			summary += fmt.Sprintf(". This SBOM: %s new, %s reappeared, %s no longer present (still open)",
				s[app.SnapshotOutcomeNew], s[app.SnapshotOutcomeReappeared], s[app.SnapshotOutcomeNoLongerPresent])
		}
		doc.Summary = summary + "."
	case app.WebhookRebuildExhausted:
		doc.Summary = fmt.Sprintf("Rebuild loop gave up on %s after %s of %s attempts; still open: %s. A person decides what happens next.",
			label, firstNonEmpty(s[app.SnapshotRebuildAttempt], "?"), firstNonEmpty(s[app.SnapshotRebuildMaxAttempts], "?"),
			firstNonEmpty(listed(s[app.SnapshotRebuildOpen]), "see the ticket"))
	case app.WebhookReviewDueSoon:
		doc.Summary = fmt.Sprintf("Review due %s for %s (%s) on %s", firstNonEmpty(dateOnly(s[app.SnapshotReviewBy]), "soon"),
			firstNonEmpty(s[app.SnapshotCVE], "a finding"), firstNonEmpty(s[app.SnapshotStance], "decision"), label)
		if o := s[app.SnapshotOwner]; o != "" {
			doc.Summary += "; owner " + o
		}
		doc.Summary += ". When the date passes the finding comes back to the queue."
	case app.WebhookDispositionStale:
		doc.Summary = fmt.Sprintf("%s on %s needs another look: %s. The %s decision still stands until someone re-decides.",
			firstNonEmpty(s[app.SnapshotCVE], "A finding"), label, firstNonEmpty(s[app.SnapshotReason], "its premise changed"),
			firstNonEmpty(s[app.SnapshotStance], "earlier"))
	case app.WebhookSLABreachDigest:
		doc.Product = firstNonEmpty(s[app.SnapshotDigestProduct], doc.Product)
		doc.Summary = fmt.Sprintf("%s: %s finding(s) passed their SLA deadline (%s): %s",
			firstNonEmpty(doc.Product, "a product"), firstNonEmpty(s[app.SnapshotDigestCount], "0"),
			strings.ReplaceAll(firstNonEmpty(s[app.SnapshotDigestBuckets], "no severity"), ",", ", "),
			firstNonEmpty(listed(s[app.SnapshotDigestCVEs]), "see the dashboard"))
		if n := s[app.SnapshotDigestReleases]; n != "" {
			doc.Summary += " across " + n + " release(s)"
		}
		doc.Summary += ". A breach changes no decision."
	default:
		return "", nil, fmt.Errorf("communication: no webhook rendering for event %q", kind)
	}
	doc.Text = doc.Summary
	if doc.Link != "" {
		doc.Text += " " + doc.Link
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return "", nil, err
	}
	return doc.Summary, body, nil
}

// listed renders a comma list as "a, b, c (+N more)" capped for a one-line message.
func listed(csv string) string {
	if strings.TrimSpace(csv) == "" {
		return ""
	}
	parts := strings.Split(csv, ",")
	if len(parts) <= webhookSummaryCVELimit {
		return strings.Join(parts, ", ")
	}
	return strings.Join(parts[:webhookSummaryCVELimit], ", ") + fmt.Sprintf(" (+%d more)", len(parts)-webhookSummaryCVELimit)
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}
