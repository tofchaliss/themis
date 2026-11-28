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

func (c *cyclesMem) LatestCycle(_ context.Context, releaseID string) (app.RebuildCycle, bool, error) {
	if r, ok := c.rows[releaseID]; ok {
		return *r, true, nil
	}
	return app.RebuildCycle{}, false, nil
}
func (c *cyclesMem) CycleByID(_ context.Context, id int64) (app.RebuildCycle, bool, error) {
	for _, r := range c.rows {
		if r.ID == id {
			return *r, true, nil
		}
	}
	return app.RebuildCycle{}, false, nil
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

type digestRows struct{ rows []app.SLABreachRecord }

func (d *digestRows) RecordSLABreach(_ context.Context, r app.SLABreachRecord) error {
	d.rows = append(d.rows, r)
	return nil
}
func (d *digestRows) PendingSLABreaches(context.Context) ([]app.SLABreachRecord, error) {
	return nil, nil
}
func (d *digestRows) MarkSLABreachesDigested(context.Context, []app.SLABreachRecord, string) error {
	return nil
}

func webhookConsumer(intents *intentStore, digest *digestRows) *inbound.Consumer {
	svc := app.NewDeliveryIntentService(intents, &intentIDs{}, clk{}, app.DeliveryIntentConfig{WebhookRoutes: map[string]string{
		app.WebhookReleaseEvaluated: "slack-sec", app.WebhookReviewDueSoon: "slack-sec",
		app.WebhookDispositionStale: "slack-sec", app.WebhookSLABreachDigest: "teams",
	}})
	return consumer(&memRepo{}).WithIntents(svc).WithSLADigest(app.NewSLADigest(digest, svc, nil, &intentIDs{}, clk{}))
}

// EDR-REMEDIATION-01 D4: with routes configured, a release evaluation also posts a webhook, the
// two per-Finding facts post one each, and an SLA breach is COLLECTED for the digest — never
// posted on its own.
func TestConsumer_WebhookEvents(t *testing.T) {
	ctx := context.Background()
	intents := newIntentStore()
	digest := &digestRows{}
	c := webhookConsumer(intents, digest)
	for _, env := range []event.Envelope{
		govEnv("env-1", "governance.release_evaluated", []byte(releaseEvaluatedPayload)),
		govEnv("env-2", "governance.review_due_soon", []byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1","CVE":"CVE-1","Stance":"accepted_risk","ReviewBy":"2026-11-05T00:00:00Z","Owner":"jane"}`)),
		govEnv("env-3", "governance.disposition_stale", []byte(`{"FindingID":"fnd-2","ReleaseID":"rel-1","CVE":"CVE-2","Stance":"not_affected","Reason":"KEV"}`)),
		govEnv("env-4", "governance.sla_breached", []byte(`{"FindingID":"fnd-3","ReleaseID":"rel-1","CVE":"CVE-3","Bucket":"critical","PeriodStart":"2026-10-01T00:00:00Z","Due":"2026-10-08T00:00:00Z"}`)),
		govEnv("env-5", "governance.review_due_soon", []byte(`{"CVE":"CVE-9"}`)), // no subject: recorded nothing, no error
	} {
		if err := c.Handle(ctx, env); err != nil {
			t.Fatalf("%s: %v", env.Type, err)
		}
	}
	var hooks []app.Intent
	for _, in := range intents.created {
		if in.Type == app.IntentWebhook {
			hooks = append(hooks, in)
		}
	}
	if len(hooks) != 3 {
		t.Fatalf("webhooks = %d: %+v", len(hooks), hooks)
	}
	if hooks[0].Snapshot[app.SnapshotWebhookEvent] != app.WebhookReleaseEvaluated || hooks[0].ReleaseID != "rel-1" {
		t.Fatalf("evaluated hook = %+v", hooks[0])
	}
	if h := hooks[1]; h.Snapshot[app.SnapshotWebhookEvent] != app.WebhookReviewDueSoon || h.FindingID != "fnd-1" ||
		h.Snapshot[app.SnapshotOwner] != "jane" || h.Snapshot[app.SnapshotReviewBy] != "2026-11-05T00:00:00Z" {
		t.Fatalf("review hook = %+v", h)
	}
	if h := hooks[2]; h.Snapshot[app.SnapshotWebhookEvent] != app.WebhookDispositionStale || h.Snapshot[app.SnapshotReason] != "KEV" || h.Snapshot[app.SnapshotReviewBy] != "" {
		t.Fatalf("stale hook = %+v", h)
	}
	mails := 0
	for _, in := range intents.created {
		if in.IsReviewDueNotification() && in.FindingID == "fnd-1" && in.Snapshot[app.SnapshotOwner] == "jane" {
			mails++
		}
	}
	if mails != 1 {
		t.Fatalf("review mails = %d, want 1", mails)
	}
	if len(digest.rows) != 1 || digest.rows[0].Bucket != "critical" || digest.rows[0].FindingID != "fnd-3" {
		t.Fatalf("digest rows = %+v", digest.rows)
	}
	// Malformed payloads are real errors (retried), not drops.
	for _, typ := range []string{"governance.review_due_soon", "governance.sla_breached"} {
		if err := c.Handle(ctx, govEnv("env-x", typ, []byte(`{not json`))); err == nil {
			t.Fatalf("%s malformed payload accepted", typ)
		}
	}
	// Delivery off: the per-Finding facts and breaches record nothing.
	off := consumer(&memRepo{})
	for _, typ := range []string{"governance.review_due_soon", "governance.sla_breached"} {
		if err := off.Handle(ctx, govEnv("env-y", typ, []byte(`{}`))); err != nil {
			t.Fatalf("%s with delivery off: %v", typ, err)
		}
	}
	for _, typ := range []string{"governance.review_due_soon", "governance.disposition_stale", "governance.sla_breached"} {
		if !inbound.Subscription.InInterest(typ) {
			t.Errorf("%s is not in the interest set", typ)
		}
	}
}

// EDR-INCIDENT-01 D1: a fix-available fact posts one webhook when routed and one mail to the
// evaluation audience, with the counts whole and the lists capped; no release is no subject;
// delivery off records nothing; a malformed payload is an error.
func TestConsumer_FixAvailable(t *testing.T) {
	ctx := context.Background()
	intents := newIntentStore()
	svc := app.NewDeliveryIntentService(intents, &intentIDs{}, clk{}, app.DeliveryIntentConfig{
		WebhookRoutes: map[string]string{app.WebhookFixAvailable: "teams-sec"}, EvaluationAudience: "release-managers"})
	c := consumer(&memRepo{}).WithIntents(svc)
	var items []string
	for i := 0; i < 25; i++ {
		items = append(items, fmt.Sprintf(`{"FindingID":"fnd-%d","CVE":"CVE-2026-%04d","Package":"kernel","Ecosystem":"rpm","Fixes":["0:4.18.0-553.80.1.el8_10"],"Advisories":["RHSA-2026:0001"]}`, i, i))
	}
	items = append(items, `{"FindingID":"fnd-x","CVE":"CVE-2026-9999","Package":"openssl","Ecosystem":"rpm","Fixes":["1:1.1.1k-14.el8_6","1:1.1.1k-15.el8_6"],"Advisories":["RHSA-2026:0002","RHSA-2026:0001"]}`)
	payload := []byte(`{"ReleaseID":"rel-1","CVECount":26,"PackageCount":2,"Items":[` + strings.Join(items, ",") + `],"OccurredAt":"2026-11-02T10:00:00Z"}`)
	if err := c.Handle(ctx, govEnv("env-fa", "governance.fix_available", payload)); err != nil {
		t.Fatal(err)
	}
	var hook, mail *app.Intent
	for i := range intents.created {
		in := &intents.created[i]
		switch {
		case in.Type == app.IntentWebhook:
			hook = in
		case in.IsFixAvailableNotification():
			mail = in
		}
	}
	if hook == nil || mail == nil {
		t.Fatalf("intents = %+v, want a webhook and a fix-available mail", intents.created)
	}
	if hook.Snapshot[app.SnapshotWebhookEvent] != app.WebhookFixAvailable || hook.ReleaseID != "rel-1" || hook.Destination != "teams-sec" {
		t.Errorf("hook = %+v", hook)
	}
	s := hook.Snapshot
	if s[app.SnapshotFixCVECount] != "26" || s[app.SnapshotFixPackageCount] != "2" || s[app.SnapshotFixAdvisories] != "RHSA-2026:0001,RHSA-2026:0002" {
		t.Errorf("counts/advisories = %q %q %q", s[app.SnapshotFixCVECount], s[app.SnapshotFixPackageCount], s[app.SnapshotFixAdvisories])
	}
	if cves := strings.Split(s[app.SnapshotFixCVEs], ","); len(cves) != 20 || cves[0] != "CVE-2026-0000" {
		t.Errorf("cve list = %v, want the first 20 sorted", cves)
	}
	if s[app.SnapshotFixPackages] != "kernel 0:4.18.0-553.80.1.el8_10;openssl 1:1.1.1k-14.el8_6;openssl 1:1.1.1k-15.el8_6" {
		t.Errorf("packages = %q", s[app.SnapshotFixPackages])
	}
	if mail.Destination != "release-managers" || mail.ReleaseID != "rel-1" || mail.Snapshot[app.SnapshotFixCVECount] != "26" {
		t.Errorf("mail = %+v", mail)
	}
	// No release: nothing recorded, no error. Unrouted: the mail still goes.
	before := len(intents.created)
	if err := c.Handle(ctx, govEnv("env-fb", "governance.fix_available", []byte(`{"CVECount":1}`))); err != nil || len(intents.created) != before {
		t.Errorf("no subject: err=%v created=%d, want nothing new", err, len(intents.created)-before)
	}
	unrouted := newIntentStore()
	uc := consumer(&memRepo{}).WithIntents(app.NewDeliveryIntentService(unrouted, &intentIDs{}, clk{}, app.DeliveryIntentConfig{}))
	if err := uc.Handle(ctx, govEnv("env-fc", "governance.fix_available", []byte(`{"ReleaseID":"rel-1","CVECount":1,"PackageCount":1,"Items":[]}`))); err != nil {
		t.Fatal(err)
	}
	if len(unrouted.created) != 1 || !unrouted.created[0].IsFixAvailableNotification() {
		t.Errorf("unrouted: created = %+v, want only the mail", unrouted.created)
	}
	if err := c.Handle(ctx, govEnv("env-fd", "governance.fix_available", []byte(`{nope`))); err == nil {
		t.Error("malformed payload must be an error")
	}
	if err := consumer(&memRepo{}).Handle(ctx, govEnv("env-fe", "governance.fix_available", []byte(`{}`))); err != nil {
		t.Errorf("delivery off: %v", err)
	}
}

// --- EDR-REBUILD-01 step R3: the two rebuild decisions on the reader path ---------------------

const rebuildDecisionPayload = `{"decision_id":"dec-1","release_id":"rel-1","product_id":"prod-1","project_id":"proj-1",
	"trigger_type":"fix_available","recommend_reason":"mode_ask","outcome":"request",
	"policy":{"cool_down_seconds":3600,"version":2,"scope_kind":"product"},
	"targeted":[{"finding_id":"f-1","cve":"CVE-2026-2","purl":"pkg:rpm/a"},{"finding_id":"f-2","cve":"CVE-2026-1","purl":"pkg:rpm/b"},
		{"finding_id":"f-3","cve":"CVE-2026-2","purl":"pkg:rpm/c"},{"finding_id":"f-4","cve":" ","purl":"pkg:rpm/d"}]}`

func decisionConsumer(openFrom string, routes map[string]string) (*inbound.Consumer, *intentStore, *loopCycles, *loopRequests) {
	intents := newIntentStore()
	svc := app.NewDeliveryIntentService(intents, &intentIDs{}, clk{}, app.DeliveryIntentConfig{
		WebhookRoutes: routes, SignedAudiences: map[string]bool{"builders": true}})
	cycles, requests := &loopCycles{}, &loopRequests{}
	loop := app.NewRebuildLoop(cycles, &postureMem{}, svc, clk{}, 2).WithDecisions(requests, openFrom)
	return consumer(&memRepo{}).WithIntents(svc).WithRebuildLoop(loop), intents, cycles, requests
}

// governance.rebuild_requested opens a cycle from the decision and records the signed request,
// with the whole decision kept for the payload; a redelivery under the same cycle adds nothing.
func TestConsumer_RebuildRequestedOpensACycleAndRecordsTheRequest(t *testing.T) {
	c, intents, cycles, requests := decisionConsumer(app.RebuildOpenFromDecision, map[string]string{app.WebhookRebuildRequested: "builders"})
	env := govEnv("env-r1", "governance.rebuild_requested", []byte(rebuildDecisionPayload))
	if err := c.Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(cycles.rows) != 1 || len(requests.rows) != 1 || len(intents.created) != 1 {
		t.Fatalf("cycles %d requests %d intents %d", len(cycles.rows), len(requests.rows), len(intents.created))
	}
	cycle, in := cycles.rows[0], intents.created[0]
	if cycle.Origin != app.CycleOriginDecision || cycle.DecisionID != "dec-1" || strings.Join(cycle.Targeted, ",") != "CVE-2026-1,CVE-2026-2" ||
		cycle.ProductID != "prod-1" || cycle.OriginEventID != "env-r1" {
		t.Errorf("cycle = %+v", cycle)
	}
	if !in.IsRebuildRequest() || in.Destination != "builders" || in.Snapshot[app.SnapshotRebuildDecision] != rebuildDecisionPayload ||
		in.Lineage.EventType != "governance.rebuild_requested" {
		t.Errorf("intent = %+v", in)
	}
	// A second decision for the same Release joins and asks for nothing.
	second := strings.Replace(rebuildDecisionPayload, "dec-1", "dec-2", 1)
	if err := c.Handle(context.Background(), govEnv("env-r2", "governance.rebuild_requested", []byte(second))); err != nil {
		t.Fatalf("handle second: %v", err)
	}
	if len(cycles.rows) != 1 || len(intents.created) != 1 || strings.Join(cycles.rows[0].Joined, ",") != "dec-2" {
		t.Errorf("a second decision must join: cycles %d intents %d joined %v", len(cycles.rows), len(intents.created), cycles.rows[0].Joined)
	}
}

// A node that still opens cycles from the posture, or has no loop, records nothing for a
// decision; a malformed decision is a real error.
func TestConsumer_RebuildRequestedIsInertUnlessSwitchedOn(t *testing.T) {
	c, intents, cycles, _ := decisionConsumer(app.RebuildOpenFromEvaluation, nil)
	if err := c.Handle(context.Background(), govEnv("env-r1", "governance.rebuild_requested", []byte(rebuildDecisionPayload))); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(cycles.rows) != 0 || len(intents.created) != 0 {
		t.Errorf("evaluation mode must ignore a decision: cycles %d intents %d", len(cycles.rows), len(intents.created))
	}
	if err := consumer(&memRepo{}).Handle(context.Background(), govEnv("env-r1", "governance.rebuild_requested", []byte(`{`))); err != nil {
		t.Errorf("no loop: %v", err)
	}
	if err := c.Handle(context.Background(), govEnv("env-r3", "governance.rebuild_requested", []byte(`{`))); err == nil {
		t.Error("a malformed decision must be an error")
	}
}

// governance.rebuild_recommended posts a webhook when its route is set, and nothing else: no
// cycle, no request.
func TestConsumer_RebuildRecommendedPostsWhenRouted(t *testing.T) {
	c, intents, cycles, _ := decisionConsumer(app.RebuildOpenFromDecision, map[string]string{app.WebhookRebuildRecommended: "sec"})
	if err := c.Handle(context.Background(), govEnv("env-c1", "governance.rebuild_recommended", []byte(rebuildDecisionPayload))); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(intents.created) != 1 || len(cycles.rows) != 0 {
		t.Fatalf("intents %d cycles %d", len(intents.created), len(cycles.rows))
	}
	in := intents.created[0]
	if in.Type != app.IntentWebhook || in.Destination != "sec" || in.Snapshot[app.SnapshotWebhookEvent] != app.WebhookRebuildRecommended ||
		in.Snapshot[app.SnapshotRebuildRecommendReason] != "mode_ask" || in.Snapshot[app.SnapshotRebuildTargetedCount] != "4" ||
		in.Snapshot[app.SnapshotTargetedCVEs] != "CVE-2026-1,CVE-2026-2" || in.ReleaseID != "rel-1" || in.IsRebuildRequest() {
		t.Errorf("intent = %+v", in)
	}

	// Unrouted: nothing. No release: nothing. No intake: nothing. Malformed: an error.
	unrouted, quiet, _, _ := decisionConsumer(app.RebuildOpenFromDecision, nil)
	if err := unrouted.Handle(context.Background(), govEnv("env-c2", "governance.rebuild_recommended", []byte(rebuildDecisionPayload))); err != nil || len(quiet.created) != 0 {
		t.Errorf("unrouted: err %v intents %d", err, len(quiet.created))
	}
	if err := c.Handle(context.Background(), govEnv("env-c3", "governance.rebuild_recommended", []byte(`{"decision_id":"d"}`))); err != nil || len(intents.created) != 1 {
		t.Errorf("no release: err %v intents %d", err, len(intents.created))
	}
	if err := consumer(&memRepo{}).Handle(context.Background(), govEnv("env-c4", "governance.rebuild_recommended", []byte(`{`))); err != nil {
		t.Errorf("no intake: %v", err)
	}
	if err := c.Handle(context.Background(), govEnv("env-c5", "governance.rebuild_recommended", []byte(`{`))); err == nil {
		t.Error("a malformed recommendation must be an error")
	}
}

// The CVE list a recommendation carries is capped; the count is whole.
func TestConsumer_RebuildRecommendedCapsTheCVEList(t *testing.T) {
	c, intents, _, _ := decisionConsumer(app.RebuildOpenFromDecision, map[string]string{app.WebhookRebuildRecommended: "sec"})
	var targeted []string
	for i := 0; i < 25; i++ {
		targeted = append(targeted, fmt.Sprintf(`{"cve":"CVE-2026-%04d"}`, i))
	}
	payload := `{"decision_id":"d","release_id":"rel-1","targeted":[` + strings.Join(targeted, ",") + `]}`
	if err := c.Handle(context.Background(), govEnv("env-c9", "governance.rebuild_recommended", []byte(payload))); err != nil {
		t.Fatalf("handle: %v", err)
	}
	in := intents.created[0]
	if n := len(strings.Split(in.Snapshot[app.SnapshotTargetedCVEs], ",")); n != 20 || in.Snapshot[app.SnapshotRebuildTargetedCount] != "25" {
		t.Errorf("listed %d of count %s", n, in.Snapshot[app.SnapshotRebuildTargetedCount])
	}
}
