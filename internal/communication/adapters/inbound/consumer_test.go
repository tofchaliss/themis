package inbound_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	govclient "github.com/themis-project/themis/internal/communication/adapters/governance"
	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/kernel/event"
)

// mkEnv wraps an event type + payload in the kernel Envelope the consumer now handles
// (M5 EB-02). The other envelope fields are transport metadata the ACL does not read.
func mkEnv(typ string, payload []byte) event.Envelope {
	return event.Envelope{Type: typ, Payload: payload}
}

// memRepo records only the publishable-queue upserts; the other Repository methods are
// unused by the inbound path.
type memRepo struct{ queue []app.QueueEntry }

func (r *memRepo) CurrentPublication(context.Context, string, string, domain.ArtifactType, string) (domain.Publication, bool, error) {
	return domain.Publication{}, false, nil
}
func (r *memRepo) GetByID(context.Context, domain.PublicationID) (domain.Publication, error) {
	return domain.Publication{}, nil
}
func (r *memRepo) Save(context.Context, domain.Publication, *domain.Publication, int, []app.OutboxNote) error {
	return nil
}
func (r *memRepo) MarkPublishable(_ context.Context, e app.QueueEntry) error {
	r.queue = append(r.queue, e)
	return nil
}
func (r *memRepo) UndeliveredPublications(context.Context, int) ([]domain.Publication, error) {
	return nil, nil
}
func (r *memRepo) UpdateDelivery(context.Context, domain.Publication, int, []app.OutboxNote) error {
	return nil
}
func (r *memRepo) ListByRelease(context.Context, string) ([]domain.Publication, error) {
	return nil, nil
}
func (r *memRepo) PublishableQueue(context.Context) ([]app.QueueEntry, error) { return nil, nil }
func (r *memRepo) PrunePayloads(context.Context, time.Time) (int, error)      { return 0, nil }

type ids struct{}

func (ids) NewID() string { return "pub-x" }

type clk struct{}

func (clk) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func consumer(repo *memRepo) *inbound.Consumer {
	svc := app.NewPublicationService(repo, nil, serializer.Default(), ids{}, clk{})
	return inbound.NewConsumer(svc)
}

func TestConsumer_PositionEstablished(t *testing.T) {
	repo := &memRepo{}
	payload := []byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1","FaultlineID":"fl-1","CVE":"CVE-2024-1","Version":1,"Stance":"not_affected"}`)
	if err := consumer(repo).Handle(context.Background(), mkEnv("governance.position_established", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(repo.queue) != 1 {
		t.Fatalf("queue = %d, want 1", len(repo.queue))
	}
	e := repo.queue[0]
	if e.FindingID != "fnd-1" || e.ReleaseID != "rel-1" || e.CVE != "CVE-2024-1" || e.Stance != domain.StanceNotAffected || e.Stale {
		t.Errorf("entry = %+v", e)
	}
}

func TestConsumer_PositionRevisedMarksStale(t *testing.T) {
	repo := &memRepo{}
	payload := []byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1","FaultlineID":"fl-1","CVE":"CVE-1","Version":2,"Stance":"mitigated"}`)
	if err := consumer(repo).Handle(context.Background(), mkEnv("governance.position_revised", payload)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(repo.queue) != 1 || !repo.queue[0].Stale || repo.queue[0].Version != 2 {
		t.Errorf("revised entry = %+v", repo.queue)
	}
}

func TestConsumer_UnknownTypeIgnored(t *testing.T) {
	repo := &memRepo{}
	if err := consumer(repo).Handle(context.Background(), mkEnv("governance.finding_resolved", []byte(`{}`))); err != nil {
		t.Errorf("unknown type should be ignored, got %v", err)
	}
	if len(repo.queue) != 0 {
		t.Error("unknown event must not touch the queue")
	}
}

func TestConsumer_MalformedPayloads(t *testing.T) {
	c := consumer(&memRepo{})
	for _, evt := range []string{"governance.position_established", "governance.position_revised"} {
		if err := c.Handle(context.Background(), mkEnv(evt, []byte("{not json"))); err == nil {
			t.Errorf("%s: malformed payload should error", evt)
		}
	}
}

// --- N-M1a: outward-delivery intents -------------------------------------------------------

// intentStore is an in-memory DeliveryIntents double reproducing the one store behaviour the
// mapping depends on: idempotence on the originating event id, per intent type.
type intentStore struct {
	created []app.Intent
	byEvent map[string]app.Intent
}

func newIntentStore() *intentStore { return &intentStore{byEvent: map[string]app.Intent{}} }

func (s *intentStore) CreateIntent(_ context.Context, in app.Intent) (app.Intent, error) {
	if in.OriginEventID != "" {
		key := in.OriginEventID + "|" + string(in.Type) // one intent per (event, type) — N-M2f
		if existing, ok := s.byEvent[key]; ok {
			return existing, nil
		}
		s.byEvent[key] = in
	}
	s.created = append(s.created, in)
	return in, nil
}

func (s *intentStore) GetIntent(context.Context, string) (app.Intent, error) {
	return app.Intent{}, app.ErrIntentNotFound
}
func (s *intentStore) GetPendingForWork(context.Context, time.Time, int) ([]app.Intent, error) {
	return nil, nil
}
func (s *intentStore) RecordAttempt(context.Context, app.Attempt) error               { return nil }
func (s *intentStore) MarkDelivered(context.Context, string, map[string]string) error { return nil }
func (s *intentStore) MarkDeadLetter(context.Context, string, string) error           { return nil }
func (s *intentStore) CancelIntent(context.Context, string) error                     { return nil }
func (s *intentStore) ListDeadLetters(context.Context, time.Time, int) ([]app.Intent, error) {
	return nil, nil
}
func (s *intentStore) RetryIntent(context.Context, string) error { return nil }

type intentIDs struct{ n int }

func (g *intentIDs) NewID() string { g.n++; return fmt.Sprintf("int-%d", g.n) }

// deliveringConsumer wires a consumer with the delivery intake attached.
func deliveringConsumer(intents *intentStore) *inbound.Consumer {
	svc := app.NewDeliveryIntentService(intents, &intentIDs{}, clk{}, app.DeliveryIntentConfig{})
	return consumer(&memRepo{}).WithIntents(svc)
}

// govEnv is a Governance envelope carrying the identity fields the intent's lineage records.
func govEnv(id, typ string, payload []byte) event.Envelope {
	return event.Envelope{
		ID: id, Type: typ, SourceContext: "governance", Subject: "fnd-1",
		SchemaRef: typ + ".v1", CorrelationID: "corr-1",
		OccurredAt: time.Unix(1_700_000_000, 0).UTC(), Payload: payload,
	}
}

// releaseEvaluatedPayload is governance.release_evaluated.v1 for an upload (cause new_sbom).
const releaseEvaluatedPayload = `{"product_id":"prod-1","project_id":"prj-1","release_id":"rel-1","sbom_id":"ev-1",` +
	`"severity_counts":{"critical":1,"high":2,"medium":0,"low":0,"unknown":0},"cause":"new_sbom"}`

// rediscoveryPayload is the same Release re-evaluated by the re-discovery sweep: a real posture
// change with nothing built (M2-3).
const rediscoveryPayload = `{"product_id":"prod-1","project_id":"prj-1","release_id":"rel-1","sbom_id":"ev-1",` +
	`"severity_counts":{"critical":1,"high":2,"medium":0,"low":0,"unknown":0},"cause":"rediscovery"}`

// N-M2c: ONE Release evaluation after a new SBOM is ONE ticket intent, and it names the product
// and the project the event carries — the reader still performs no Registry read. N-M2f: the
// same event also asks for ONE mail to the governed audience, after the ticket.
func TestReleaseEvaluatedMapping_OnlyNewSBOM_CreatesIntents(t *testing.T) {
	intents := newIntentStore()
	env := govEnv("env-1", "governance.release_evaluated", []byte(releaseEvaluatedPayload))
	if err := deliveringConsumer(intents).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 2 {
		t.Fatalf("created %d intents, want 2 (ticket + evaluation mail)", len(intents.created))
	}
	mail := intents.created[1]
	if mail.Type != app.IntentEmail || !mail.IsEvaluationNotification() || mail.ReleaseID != "rel-1" ||
		mail.OriginEventID != "env-1" || mail.Destination != "security-decisions" || mail.ProductID != "prod-1" {
		t.Errorf("evaluation mail = %+v", mail)
	}
	in := intents.created[0]
	if in.Type != app.IntentJiraIssue || in.ReleaseID != "rel-1" || in.OriginEventID != "env-1" {
		t.Errorf("intent = %+v", in)
	}
	if in.ProductID != "prod-1" || in.ProjectID != "prj-1" {
		t.Errorf("product/project must come from the event: %+v", in)
	}
	if in.Lineage.EventType != "governance.release_evaluated" || in.Lineage.SourceContext != "governance" ||
		in.Lineage.CorrelationID != "corr-1" || in.Lineage.EventID != "env-1" {
		t.Errorf("lineage = %+v", in.Lineage)
	}
	if in.Snapshot["sbom_id"] != "ev-1" || in.Snapshot["cause"] != "new_sbom" ||
		in.Snapshot["product_id"] != "prod-1" || in.Snapshot["project_id"] != "prj-1" {
		t.Errorf("snapshot = %v", in.Snapshot)
	}
}

// N-M2c: the retired finding_opened proxy and a re-discovery evaluation create NO intent and
// report no error — one would ticket per Finding again, the other would ticket an unchanged build.
func TestFindingOpenedAndRediscovery_CreateNoIntents(t *testing.T) {
	intents := newIntentStore()
	c := deliveringConsumer(intents)
	for _, env := range []event.Envelope{
		govEnv("env-a", "governance.finding_opened",
			[]byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1","FaultlineID":"fl-1","CVE":"CVE-2026-1"}`)),
		govEnv("env-b", "governance.release_evaluated", []byte(rediscoveryPayload)),
	} {
		if err := c.Handle(context.Background(), env); err != nil {
			t.Fatalf("%s: %v", env.Type, err)
		}
	}
	if len(intents.created) != 0 {
		t.Fatalf("created %d intents, want 0: %+v", len(intents.created), intents.created)
	}
	if inbound.Subscription.InInterest("governance.finding_opened") {
		t.Error("finding_opened is still in the interest set; the proxy was retired by N-M2c")
	}
}

// Re-delivering the SAME envelope id must not enqueue a second ticket — the transport is
// at-least-once, so this is the normal case, not an edge case.
func TestConsumer_ReleaseEvaluatedRedeliveryCreatesNoSecondIntent(t *testing.T) {
	intents := newIntentStore()
	c := deliveringConsumer(intents)
	env := govEnv("env-1", "governance.release_evaluated", []byte(releaseEvaluatedPayload))
	for i := 0; i < 2; i++ {
		if err := c.Handle(context.Background(), env); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}
	if len(intents.created) != 2 {
		t.Fatalf("created %d intents for one event, want 2 (one per type)", len(intents.created))
	}
}

func TestConsumer_ProposalAcceptedRecordsOneDecisionMail(t *testing.T) {
	intents := newIntentStore()
	c := deliveringConsumer(intents)
	env := govEnv("env-2", "governance.proposal_accepted",
		[]byte(`{"FindingID":"fnd-1","ProposalID":"prop-1","PositionVersion":2}`))
	for i := 0; i < 2; i++ { // the second delivery is the replay
		if err := c.Handle(context.Background(), env); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}
	if len(intents.created) != 1 {
		t.Fatalf("created %d intents for one event, want 1", len(intents.created))
	}
	in := intents.created[0]
	if in.Type != app.IntentEmail || in.ProposalID != "prop-1" || in.FindingID != "fnd-1" {
		t.Errorf("intent = %+v", in)
	}
	if in.Destination != "security-decisions" {
		t.Errorf("destination = %q", in.Destination)
	}
	if in.Snapshot["position_version"] != "2" {
		t.Errorf("snapshot = %v", in.Snapshot)
	}
}

// An evaluation that names no Release records nothing and reports no error: there is no
// subject to track a fix for, and a retry would not produce one.
func TestConsumer_ReleaseEvaluatedWithoutReleaseRecordsNothing(t *testing.T) {
	intents := newIntentStore()
	env := govEnv("env-3", "governance.release_evaluated", []byte(`{"release_id":"","cause":"new_sbom"}`))
	if err := deliveringConsumer(intents).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 0 {
		t.Errorf("created %d intents, want 0", len(intents.created))
	}
}

func TestConsumer_ProposalAcceptedWithoutSubjectRecordsNothing(t *testing.T) {
	intents := newIntentStore()
	env := govEnv("env-4", "governance.proposal_accepted", []byte(`{"PositionVersion":1}`))
	if err := deliveringConsumer(intents).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 0 {
		t.Errorf("created %d intents, want 0", len(intents.created))
	}
}

func TestConsumer_DeliveryEventsMalformedPayloads(t *testing.T) {
	c := deliveringConsumer(newIntentStore())
	for _, evt := range []string{"governance.release_evaluated", "governance.proposal_accepted"} {
		if err := c.Handle(context.Background(), govEnv("env-x", evt, []byte("{not json"))); err == nil {
			t.Errorf("%s: malformed payload should error (so the event is retried, not dropped)", evt)
		}
	}
}

// Without the intake wired (delivery disabled on this node) the delivery events are inert —
// no intent, no error — while the Position events keep working.
func TestConsumer_WithoutIntentsRecordsNoIntents(t *testing.T) {
	repo := &memRepo{}
	c := consumer(repo)
	for _, evt := range []string{"governance.release_evaluated", "governance.proposal_accepted"} {
		if err := c.Handle(context.Background(), govEnv("env-5", evt, []byte(releaseEvaluatedPayload))); err != nil {
			t.Errorf("%s: %v", evt, err)
		}
	}
	if len(repo.queue) != 0 {
		t.Error("delivery events must not touch the publishable queue")
	}
}

// blockingDeliverer stands in for Jira or a mail relay that never answers. The reader holds no
// deliverer at all, which is the invariant under test: it writes the intent and returns, so an
// unreachable external system cannot stall the bus reader path.
type blockingDeliverer struct{ calls int }

func (d *blockingDeliverer) DeliverIntent(ctx context.Context, _ app.Intent) error {
	d.calls++
	<-ctx.Done() // would hang the reader if the reader ever called it
	return ctx.Err()
}

func TestConsumer_NeverDelivers(t *testing.T) {
	intents := newIntentStore()
	blocked := &blockingDeliverer{}

	// First prove the stand-in really does hang — it is what an unreachable Jira looks like.
	blockCtx, cancelBlock := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelBlock()
	if err := blocked.DeliverIntent(blockCtx, app.Intent{}); err == nil {
		t.Fatal("the blocking stand-in returned without its context being cancelled")
	}
	if blocked.calls != 1 {
		t.Fatalf("stand-in calls = %d, want 1", blocked.calls)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- deliveringConsumer(intents).Handle(ctx,
			govEnv("env-6", "governance.release_evaluated", []byte(releaseEvaluatedPayload)))
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handle: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("the event reader blocked — it must only persist the intent")
	}
	if blocked.calls != 1 {
		t.Errorf("deliverer calls = %d; handling an event must add none", blocked.calls)
	}
	if len(intents.created) != 2 {
		t.Errorf("the reader must persist exactly the two intents, got %d", len(intents.created))
	}
}

// The subscription has to DISPATCH on the new types; an event outside the interest set never
// reaches Handle, so an undeclared mapping is dead code in production.
func TestSubscriptionDispatchesOnTheDeliveryTriggers(t *testing.T) {
	for _, typ := range []string{"governance.release_evaluated", "governance.proposal_accepted"} {
		if !inbound.Subscription.InInterest(typ) {
			t.Errorf("%s is not in the Communication interest set", typ)
		}
	}
}

// --- Auth-enabled estate: the reader's own read must be authenticated -----------------------

// authedPostureStub is a Governance node running with THEMIS_AUTH_REQUIRED=1: every read without
// the key is a 401.
func authedPostureStub(t *testing.T, key string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`[{"finding_id":"fnd-1","cve":"CVE-2026-1","base_score":95}]`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// materializingConsumer is the PRODUCTION shape of the reader on an auth-enabled estate: the intent
// service renders the ticket payload through the outward serializer, which reads the Release posture
// over Governance's read API — so the reader's own HTTP read is in the path, with whatever credential
// the client was given.
func materializingConsumer(intents *intentStore, governanceURL, apiKey string) *inbound.Consumer {
	posture := govclient.NewClient(governanceURL, nil).WithAPIKey(apiKey)
	svc := app.NewDeliveryIntentService(intents, &intentIDs{}, clk{}, app.DeliveryIntentConfig{}).
		WithPayloadRenderer(serializer.NewOutwardRenderer(posture))
	return consumer(&memRepo{}).WithIntents(svc)
}

// WITH the key the ticket intent is recorded, payload and all. This is the enterprise-VM case of
// 2026-10-05 and the reason the read seam carries a credential at all.
func TestConsumer_RecordsTheJiraIntentOnAnAuthEnabledEstate(t *testing.T) {
	const key = "read-scoped-key-abc123"
	srv := authedPostureStub(t, key)
	intents := newIntentStore()

	env := govEnv("env-1", "governance.release_evaluated", []byte(releaseEvaluatedPayload))
	if err := materializingConsumer(intents, srv.URL, key).Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 2 {
		t.Fatalf("created %d intents, want 2", len(intents.created))
	}
	in := intents.created[0]
	if in.PayloadSHA256 == "" || len(in.PayloadBytes) == 0 {
		t.Fatalf("the intent carries no materialized payload: %q", in.PayloadSHA256)
	}
	// The posture the authenticated read returned is IN the ticket: one Critical, its id listed.
	if body := string(in.PayloadBytes); !strings.Contains(body, "Critical: 1") || !strings.Contains(body, "CVE-2026-1") {
		t.Errorf("payload does not reflect the posture read:\n%s", body)
	}
}

// WITHOUT the key, the same estate reproduces the defect exactly: the read 401s, NOTHING is
// recorded, and Handle returns an error so the envelope is retried rather than dropped.
//
// Both halves are the regression. The error is correct behaviour — an intent whose content could not
// be determined must not be queued (D-N-3) — but it is also a LOOP: the retry will 401 again, which
// is why the error has to name the credential rather than look like a broken endpoint.
func TestConsumer_UnauthenticatedPostureReadRecordsNothingAndRetries(t *testing.T) {
	srv := authedPostureStub(t, "read-scoped-key-abc123")
	intents := newIntentStore()

	env := govEnv("env-1", "governance.release_evaluated", []byte(releaseEvaluatedPayload))
	err := materializingConsumer(intents, srv.URL, "").Handle(context.Background(), env)
	if err == nil {
		t.Fatal("a 401 on the posture read must surface, so the envelope is retried")
	}
	for _, want := range []string{"401", "THEMIS_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q — a bare status reads as a broken endpoint", err, want)
		}
	}
	if len(intents.created) != 0 {
		t.Errorf("an intent was recorded from a refused read: %+v", intents.created)
	}
}

// --- N-M2i: the rebuild loop on the reader path ---------------------------------------------

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

type postureMem struct{ rows []app.ReleaseSeverityRow }

func (p *postureMem) ReleaseSeverity(context.Context, string) ([]app.ReleaseSeverityRow, error) {
	return p.rows, nil
}

// With the loop wired, a new_sbom evaluation that leaves Critical/High Findings records THREE
// intents in order — ticket, mail (both carrying the loop's decision), then the rebuild — and a
// clean evaluation records the two with no loop section and no rebuild.
func TestConsumer_ReleaseEvaluatedDrivesTheRebuildLoop(t *testing.T) {
	intents := newIntentStore()
	svc := app.NewDeliveryIntentService(intents, &intentIDs{}, clk{}, app.DeliveryIntentConfig{})
	posture := &postureMem{rows: []app.ReleaseSeverityRow{{CVE: "CVE-2026-1", BaseScore: 95}, {CVE: "CVE-2026-2", BaseScore: 30}}}
	loop := app.NewRebuildLoop(&cyclesMem{rows: map[string]*app.RebuildCycle{}}, posture, svc, clk{}, 2)
	c := consumer(&memRepo{}).WithIntents(svc).WithRebuildLoop(loop)

	if err := c.Handle(context.Background(), govEnv("env-1", "governance.release_evaluated", []byte(releaseEvaluatedPayload))); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 3 {
		t.Fatalf("created %d intents, want ticket + mail + rebuild", len(intents.created))
	}
	ticket, mail, rebuild := intents.created[0], intents.created[1], intents.created[2]
	if ticket.Type != app.IntentJiraIssue || mail.Type != app.IntentEmail || rebuild.Type != app.IntentCIRebuild {
		t.Fatalf("types = %s %s %s", ticket.Type, mail.Type, rebuild.Type)
	}
	for _, in := range []app.Intent{ticket, mail} {
		if in.Snapshot[app.SnapshotRebuildState] != app.OutcomeOpened || in.Snapshot[app.SnapshotRebuildTargeted] != "CVE-2026-1" || in.Snapshot[app.SnapshotRebuildAttempt] != "1" {
			t.Errorf("%s snapshot lacks the loop decision: %v", in.Type, in.Snapshot)
		}
	}
	if rebuild.OriginEventID != "env-1" || rebuild.ReleaseID != "rel-1" || rebuild.ProductID != "prod-1" || rebuild.Snapshot[app.SnapshotTargetedCVEs] != "CVE-2026-1" {
		t.Errorf("rebuild = %+v", rebuild)
	}

	// Clean evaluation of another Release: two intents, no loop section, no rebuild.
	posture.rows = []app.ReleaseSeverityRow{{CVE: "CVE-2026-2", BaseScore: 30}}
	clean := `{"product_id":"prod-1","project_id":"prj-1","release_id":"rel-2","sbom_id":"ev-9","severity_counts":{},"cause":"new_sbom"}`
	if err := c.Handle(context.Background(), govEnv("env-2", "governance.release_evaluated", []byte(clean))); err != nil {
		t.Fatalf("handle clean: %v", err)
	}
	if len(intents.created) != 5 || intents.created[3].Snapshot[app.SnapshotRebuildState] != "" || intents.created[4].Type != app.IntentEmail {
		t.Errorf("clean evaluation → %d intents (%v)", len(intents.created), intents.created[3].Snapshot)
	}
	// A rediscovery never reaches the loop.
	if err := c.Handle(context.Background(), govEnv("env-3", "governance.release_evaluated", []byte(rediscoveryPayload))); err != nil || len(intents.created) != 5 {
		t.Errorf("rediscovery: err %v, intents %d", err, len(intents.created))
	}
}

// EDR-REMEDIATION-01 D3: the upload outcome on the event is copied onto both intents' snapshots,
// and an event without one adds no outcome keys (the renderer then writes no section).
func TestReleaseEvaluated_CarriesTheUploadOutcome(t *testing.T) {
	payload := `{"product_id":"prod-1","project_id":"prj-1","release_id":"rel-1","sbom_id":"ev-1","cause":"new_sbom",
		"severity_counts":{"critical":0,"high":0,"medium":0,"low":0},
		"upload_outcome":{"new":2,"reappeared":0,"no_longer_present":3,"unchanged":9,"not_judged":1,
			"new_cves":["CVE-1","CVE-2"],"no_longer_present_cves":["CVE-7","CVE-8","CVE-9"],"has_baseline":true}}`
	intents := newIntentStore()
	if err := deliveringConsumer(intents).Handle(context.Background(), govEnv("env-o", "governance.release_evaluated", []byte(payload))); err != nil {
		t.Fatal(err)
	}
	for _, in := range intents.created {
		s := in.Snapshot
		if s[app.SnapshotOutcomeNew] != "2" || s[app.SnapshotOutcomeNoLongerPresent] != "3" || s[app.SnapshotOutcomeUnchanged] != "9" ||
			s[app.SnapshotOutcomeNotJudged] != "1" || s[app.SnapshotOutcomeReappeared] != "0" || s[app.SnapshotOutcomeGoneCVEs] != "CVE-7,CVE-8,CVE-9" ||
			s[app.SnapshotOutcomeNewCVEs] != "CVE-1,CVE-2" || s[app.SnapshotOutcomeHasBaseline] != "true" {
			t.Fatalf("%s snapshot = %v", in.Type, s)
		}
	}
	plain := newIntentStore()
	if err := deliveringConsumer(plain).Handle(context.Background(), govEnv("env-p", "governance.release_evaluated", []byte(releaseEvaluatedPayload))); err != nil {
		t.Fatal(err)
	}
	if _, ok := plain.created[0].Snapshot[app.SnapshotOutcomeNew]; ok {
		t.Fatal("an event without an outcome produced outcome keys")
	}
}
