package delivery_test

import (
	"context"
	"strings"
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

// callbacksMem is the callback port for the worker-level test.
type callbacksMem struct{ rows []app.RebuildCallback }

func (c *callbacksMem) RecordCallback(_ context.Context, cb app.RebuildCallback) (app.RebuildCallback, error) {
	c.rows = append(c.rows, cb)
	return cb, nil
}
func (c *callbacksMem) ListCallbacks(context.Context, string) ([]app.RebuildCallback, error) {
	return c.rows, nil
}

// N-M2f/N-M2h, worker level: a callback ALONE has no side effects — no intent is created, the
// worker has nothing new to send, Jira and mail stay untouched. Jira and mail follow the
// EVALUATION of the SBOM the callback names (step 2 → 4 of M2-8), never the callback (step 1).
func TestCallbackAlone_NoSideEffects(t *testing.T) {
	h := newHarness(t, testConfig())
	cbs := &callbacksMem{}
	h.svc = h.svc.WithRebuildCallbacks(cbs)
	ctx := context.Background()

	rebuild, err := h.svc.EnqueueCIRebuild(ctx, app.IntentLineage{}, "", "rel-1", "prod-1", "prj-1", "ev-1", []string{"CVE-2026-1"}, 1, nil)
	if err != nil {
		t.Fatalf("enqueue rebuild: %v", err)
	}
	if sent := h.runOnce(t); sent != 1 || h.rebuild.Calls() != 1 {
		t.Fatalf("the rebuild intent itself is sent once, got %d (rebuild sender calls %d)", sent, h.rebuild.Calls())
	}
	intentsBefore := len(h.intents.order)

	for i := 0; i < 2; i++ { // the job retries its callback
		if _, err := h.svc.RecordRebuildCallback(ctx, app.RebuildCallback{IntentID: rebuild.ID, SBOMID: "ev-2", ImageDigest: "sha256:abc", BuildID: "77"}); err != nil {
			t.Fatalf("callback %d: %v", i, err)
		}
	}
	if sent := h.runOnce(t); sent != 0 {
		t.Errorf("a callback made the worker send %d intents, want 0", sent)
	}
	if len(h.intents.order) != intentsBefore {
		t.Errorf("a callback created %d intents", len(h.intents.order)-intentsBefore)
	}
	if h.jira.Calls() != 0 || h.mail.Calls() != 0 {
		t.Errorf("jira=%d mail=%d after a callback, want 0/0 — they follow the evaluation, not the build", h.jira.Calls(), h.mail.Calls())
	}
	if in := h.intents.get(t, rebuild.ID); in.State != app.IntentDelivered {
		t.Errorf("the rebuild intent changed state to %s", in.State)
	}
	if len(cbs.rows) != 2 || cbs.rows[0].IntentID != rebuild.ID {
		t.Errorf("callbacks recorded = %+v (the memory port does not deduplicate; the store does)", cbs.rows)
	}
}

// cyclesMem is the cycle port for the worker-level loop tests.
type cyclesMem struct{ rows map[string]*app.RebuildCycle }

func (c *cyclesMem) OpenCycle(_ context.Context, releaseID string) (app.RebuildCycle, bool, error) {
	if r, ok := c.rows[releaseID]; ok && r.State == app.CycleOpen {
		return *r, true, nil
	}
	return app.RebuildCycle{}, false, nil
}
func (c *cyclesMem) CreateCycle(_ context.Context, cy app.RebuildCycle) (app.RebuildCycle, error) {
	cy.ID = int64(len(c.rows) + 1)
	c.rows[cy.ReleaseID] = &cy
	return cy, nil
}
func (c *cyclesMem) UpdateCycle(_ context.Context, cy app.RebuildCycle) error {
	c.rows[cy.ReleaseID] = &cy
	return nil
}

// loopHarness is the worker harness with the loop on the consumer and a mutable posture.
type loopHarness struct {
	*harness
	posture  *mutablePosture
	consumer *inbound.Consumer
}

type mutablePosture struct{ rows []app.ReleaseSeverityRow }

func (p *mutablePosture) ReleaseSeverity(context.Context, string) ([]app.ReleaseSeverityRow, error) {
	return p.rows, nil
}

func newLoopHarness(t *testing.T, max int) *loopHarness {
	t.Helper()
	cfg := testConfig()
	cfg.RebuildMaxAttempts = max
	h := newHarness(t, cfg)
	posture := &mutablePosture{}
	h.svc = h.svc.WithPayloadRenderer(serializer.NewOutwardRenderer(posture))
	loop := app.NewRebuildLoop(&cyclesMem{rows: map[string]*app.RebuildCycle{}}, posture, h.svc, fixedClock{}, cfg.RebuildMaxAttempts)
	return &loopHarness{harness: h, posture: posture, consumer: inbound.NewConsumer(nil).WithIntents(h.svc).WithRebuildLoop(loop)}
}

func (h *loopHarness) evaluate(t *testing.T, envID, sbomID string) {
	t.Helper()
	env := releaseEvaluated(envID, "new_sbom")
	env.Payload = []byte(`{"product_id":"prod-1","project_id":"prj-1","release_id":"rel-1","sbom_id":"` + sbomID + `","severity_counts":{},"cause":"new_sbom"}`)
	if err := h.consumer.Handle(context.Background(), env); err != nil {
		t.Fatalf("evaluate %s: %v", envID, err)
	}
}

// drain runs passes until nothing is due, so a count of sends does not depend on the batch size.
func (h *loopHarness) drain(t *testing.T) {
	t.Helper()
	for i := 0; i < 10; i++ {
		if h.runOnce(t) == 0 {
			return
		}
	}
	t.Fatal("the queue did not drain in ten passes")
}

func (h *loopHarness) lastOfType(typ app.IntentType) app.Intent {
	var last app.Intent
	for _, id := range h.intents.order {
		if in := h.intents.intents[id]; in.Type == typ {
			last = *in
		}
	}
	return last
}

// M2-8 / N-M2i at worker level: the loop raises a rebuild on open, another on a partial result,
// and NOTHING after success or exhaustion — a stop is the decision, not a pause — while the
// ticket and the mail still go out on every evaluation.
func TestStopOnSuccessOrExhaustion_NoFurtherIntents(t *testing.T) {
	// Exhaustion: limit 2, the target never closes.
	h := newLoopHarness(t, 2)
	h.posture.rows = []app.ReleaseSeverityRow{{CVE: "CVE-2026-1", BaseScore: 95}}
	h.evaluate(t, "env-1", "ev-1")
	h.evaluate(t, "env-2", "ev-2")
	h.evaluate(t, "env-3", "ev-3") // the second rebuild's result: still open ⇒ exhausted
	h.evaluate(t, "env-4", "ev-4") // a further new SBOM: a NEW cycle opens (attempt 1 again)
	h.drain(t)
	if n := h.intents.countByType(app.IntentCIRebuild); n != 3 {
		t.Errorf("rebuild intents = %d, want 2 for the exhausted cycle + 1 for the new one", n)
	}
	if h.rebuild.Calls() != 3 || h.jira.Calls() != 4 || h.mail.Calls() != 4 {
		t.Errorf("sends: rebuild=%d jira=%d mail=%d, want 3/4/4", h.rebuild.Calls(), h.jira.Calls(), h.mail.Calls())
	}

	// Success: the target closes after the first rebuild; nothing more is raised.
	s := newLoopHarness(t, 2)
	s.posture.rows = []app.ReleaseSeverityRow{{CVE: "CVE-2026-1", BaseScore: 95}}
	s.evaluate(t, "env-1", "ev-1")
	s.posture.rows = nil
	s.evaluate(t, "env-2", "ev-2")
	s.evaluate(t, "env-3", "ev-3") // clean again: no cycle, no rebuild
	s.drain(t)
	if n := s.intents.countByType(app.IntentCIRebuild); n != 1 {
		t.Errorf("rebuild intents after success = %d, want 1", n)
	}
	if last := s.lastOfType(app.IntentJiraIssue); last.Snapshot[app.SnapshotRebuildState] != "" {
		t.Errorf("a clean evaluation after success must carry no loop section: %v", last.Snapshot)
	}
}

// M2-8: exhaustion TELLS A PERSON — the ticket and the mail of the exhausting evaluation say the
// attempts are spent and what is still open, and say that Themis will not rebuild again in this
// cycle; a Finding is never resolved by it.
func TestNotifyPersonOnExhaustion(t *testing.T) {
	h := newLoopHarness(t, 1)
	h.posture.rows = []app.ReleaseSeverityRow{{CVE: "CVE-2026-1", BaseScore: 95}, {CVE: "CVE-2026-2", BaseScore: 80}}
	h.evaluate(t, "env-1", "ev-1")
	h.posture.rows = []app.ReleaseSeverityRow{{CVE: "CVE-2026-2", BaseScore: 80}}
	h.evaluate(t, "env-2", "ev-2")
	h.drain(t)

	for _, typ := range []app.IntentType{app.IntentJiraIssue, app.IntentEmail} {
		in := h.lastOfType(typ)
		_, body := app.SplitPayload(in.PayloadBytes)
		text := string(body)
		for _, want := range []string{"ATTEMPTS EXHAUSTED (1 of 1)", "will not ask for another rebuild", "A person decides", "Still open", "CVE-2026-2", "Closed", "CVE-2026-1", "never auto-resolved"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s body lacks %q:\n%s", typ, want, text)
			}
		}
		if in.Snapshot[app.SnapshotRebuildState] != app.OutcomeExhausted {
			t.Errorf("%s state = %q", typ, in.Snapshot[app.SnapshotRebuildState])
		}
	}
	if n := h.intents.countByType(app.IntentCIRebuild); n != 1 {
		t.Errorf("rebuild intents = %d, want the one attempt", n)
	}
	// The opening ticket said what it was doing, too.
	var first app.Intent
	for _, id := range h.intents.order {
		if in := h.intents.intents[id]; in.Type == app.IntentJiraIssue {
			first = *in
			break
		}
	}
	if _, body := app.SplitPayload(first.PayloadBytes); !strings.Contains(string(body), "Opened: Critical and High Findings remain") || !strings.Contains(string(body), "attempt 1 of 1") {
		t.Errorf("opening ticket:\n%s", body)
	}
}
