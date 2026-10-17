package delivery_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/kernel/event"
)

// postureStub answers Governance's posture read for the renderer with a fixed estate.
type postureStub struct{ rows []app.ReleaseSeverityRow }

func (p postureStub) ReleaseSeverity(context.Context, string) ([]app.ReleaseSeverityRow, error) {
	return p.rows, nil
}

func releaseEvaluated(id, cause string) event.Envelope {
	return event.Envelope{
		ID: id, Type: "governance.release_evaluated", SourceContext: "governance", Subject: "rel-1",
		SchemaRef: "governance.release_evaluated.v1", CorrelationID: "corr-1", OccurredAt: epoch,
		Payload: []byte(`{"product_id":"prod-1","project_id":"prj-1","release_id":"rel-1","sbom_id":"ev-2",` +
			`"severity_counts":{"critical":1,"high":1,"medium":0,"low":0},"cause":"` + cause + `"}`),
	}
}

// N-M2f, worker level: an evaluation after a new SBOM produces exactly ONE ticket send and ONE
// mail send; a redelivery of the same event adds nothing; the ticket send is the full-replace
// update, so a SECOND evaluation (a new event) sends the ticket again with the then-current
// posture and is idempotent on the ticket itself (M1b-4). A rediscovery evaluation produces
// neither. Jira and mail happen at this step and nowhere earlier (M2-8).
func TestPostEvaluationOnly_ProducesTicketAndMail(t *testing.T) {
	h := newHarness(t, testConfig())
	h.svc = h.svc.WithPayloadRenderer(serializer.NewOutwardRenderer(postureStub{rows: []app.ReleaseSeverityRow{
		{CVE: "CVE-2026-1", BaseScore: 95}, {CVE: "CVE-2026-2", BaseScore: 75},
	}}))
	consumer := inbound.NewConsumer(nil).WithIntents(h.svc)
	ctx := context.Background()

	for i := 0; i < 2; i++ { // the second delivery is the transport's replay
		if err := consumer.Handle(ctx, releaseEvaluated("env-1", "new_sbom")); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}
	if n := h.intents.countByType(app.IntentJiraIssue); n != 1 {
		t.Fatalf("ticket intents = %d, want 1", n)
	}
	if n := h.intents.countByType(app.IntentEmail); n != 1 {
		t.Fatalf("mail intents = %d, want 1", n)
	}
	if sent := h.runOnce(t); sent != 2 {
		t.Fatalf("first pass sent %d, want the ticket and the mail", sent)
	}
	if h.jira.Calls() != 1 || h.mail.Calls() != 1 {
		t.Errorf("jira=%d mail=%d, want one each", h.jira.Calls(), h.mail.Calls())
	}
	if sent := h.runOnce(t); sent != 0 {
		t.Errorf("second pass sent %d, want nothing — both intents are delivered", sent)
	}

	// The mail carries the posture, not the callback: no build, no digest, a Release.
	var mail app.Intent
	for _, id := range h.intents.order {
		if in := h.intents.intents[id]; in.Type == app.IntentEmail {
			mail = *in
		}
	}
	subject, body := app.SplitPayload(mail.PayloadBytes)
	if subject != "Themis evaluated Release rel-1 - Critical 1, High 1" || len(body) == 0 || mail.Destination != "security-decisions" {
		t.Errorf("mail = %q to %q", subject, mail.Destination)
	}

	// A rediscovery evaluation — a posture change with nothing built — asks for nothing.
	if err := consumer.Handle(ctx, releaseEvaluated("env-2", "rediscovery")); err != nil {
		t.Fatalf("rediscovery: %v", err)
	}
	if sent := h.runOnce(t); sent != 0 || h.jira.Calls() != 1 || h.mail.Calls() != 1 {
		t.Errorf("rediscovery sent %d (jira=%d mail=%d), want nothing", sent, h.jira.Calls(), h.mail.Calls())
	}

	// The next evaluation is a new event: the ticket is updated (full replace) and the mail sent
	// again — once each.
	h.advance(time.Minute)
	if err := consumer.Handle(ctx, releaseEvaluated("env-3", "new_sbom")); err != nil {
		t.Fatalf("second evaluation: %v", err)
	}
	if sent := h.runOnce(t); sent != 2 || h.jira.Calls() != 2 || h.mail.Calls() != 2 {
		t.Errorf("second evaluation sent %d (jira=%d mail=%d), want 2 / 2 / 2", sent, h.jira.Calls(), h.mail.Calls())
	}
}
