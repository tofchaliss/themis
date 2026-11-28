package app_test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
)

// requestsMem is an in-memory RebuildRequests. fail names a method that answers with an error.
type requestsMem struct {
	rows    map[string]*app.RebuildRequest
	order   []string
	holds   map[string]app.RebuildHold
	sboms   map[string]string
	fail    map[string]error
	cleared int
}

func newRequestsMem() *requestsMem {
	return &requestsMem{rows: map[string]*app.RebuildRequest{}, holds: map[string]app.RebuildHold{}, sboms: map[string]string{}, fail: map[string]error{}}
}

func (m *requestsMem) CreateRequest(_ context.Context, r app.RebuildRequest) error {
	if err := m.fail["CreateRequest"]; err != nil {
		return err
	}
	if _, ok := m.rows[r.IntentID]; !ok {
		m.rows[r.IntentID] = &r
		m.order = append(m.order, r.IntentID)
	}
	return nil
}
func (m *requestsMem) RequestByIntent(_ context.Context, id string) (app.RebuildRequest, error) {
	if err := m.fail["RequestByIntent"]; err != nil {
		return app.RebuildRequest{}, err
	}
	if r, ok := m.rows[id]; ok {
		return *r, nil
	}
	return app.RebuildRequest{}, app.ErrRebuildRequestNotFound
}
func (m *requestsMem) ListRequests(_ context.Context, cycleID int64) ([]app.RebuildRequest, error) {
	if err := m.fail["ListRequests"]; err != nil {
		return nil, err
	}
	out := []app.RebuildRequest{}
	for _, id := range m.order {
		if r := m.rows[id]; r.CycleID == cycleID {
			out = append(out, *r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Attempt != out[j].Attempt {
			return out[i].Attempt < out[j].Attempt
		}
		return out[i].Try < out[j].Try
	})
	return out, nil
}
func (m *requestsMem) LatestRequest(ctx context.Context, cycleID int64) (app.RebuildRequest, bool, error) {
	if err := m.fail["LatestRequest"]; err != nil {
		return app.RebuildRequest{}, false, err
	}
	list, _ := m.ListRequests(ctx, cycleID)
	if len(list) == 0 {
		return app.RebuildRequest{}, false, nil
	}
	return list[len(list)-1], true, nil
}
func (m *requestsMem) UpdateRequest(_ context.Context, r app.RebuildRequest) error {
	if err := m.fail["UpdateRequest"]; err != nil {
		return err
	}
	m.rows[r.IntentID] = &r
	return nil
}
func (m *requestsMem) LastDeliveredAt(_ context.Context, releaseID string) (time.Time, bool, error) {
	if err := m.fail["LastDeliveredAt"]; err != nil {
		return time.Time{}, false, err
	}
	var last time.Time
	for _, r := range m.rows {
		if r.ReleaseID == releaseID && r.DeliveredAt.After(last) {
			last = r.DeliveredAt
		}
	}
	return last, !last.IsZero(), nil
}
func (m *requestsMem) SilentRequests(_ context.Context, before time.Time) ([]app.RebuildRequest, error) {
	if err := m.fail["SilentRequests"]; err != nil {
		return nil, err
	}
	var out []app.RebuildRequest
	for _, id := range m.order {
		if r := m.rows[id]; r.State == app.RequestDelivered && r.Channel == app.ChannelWebhook && r.DeliveredAt.Before(before) {
			out = append(out, *r)
		}
	}
	return out, nil
}
func (m *requestsMem) SaveHold(_ context.Context, h app.RebuildHold) error {
	if err := m.fail["SaveHold"]; err != nil {
		return err
	}
	m.holds[h.ReleaseID] = h
	return nil
}
func (m *requestsMem) ClearHold(_ context.Context, releaseID string) error {
	if err := m.fail["ClearHold"]; err != nil {
		return err
	}
	m.cleared++
	delete(m.holds, releaseID)
	return nil
}
func (m *requestsMem) Hold(_ context.Context, releaseID string) (app.RebuildHold, bool, error) {
	if err := m.fail["Hold"]; err != nil {
		return app.RebuildHold{}, false, err
	}
	h, ok := m.holds[releaseID]
	return h, ok, nil
}
func (m *requestsMem) SaveLastSBOM(_ context.Context, releaseID, sbomID string, _ time.Time) error {
	if err := m.fail["SaveLastSBOM"]; err != nil {
		return err
	}
	m.sboms[releaseID] = sbomID
	return nil
}
func (m *requestsMem) LastSBOM(_ context.Context, releaseID string) (string, error) {
	return m.sboms[releaseID], m.fail["LastSBOM"]
}

// set forces the state of a request, as the delivery worker or the connector would.
func (m *requestsMem) set(id, state string, at time.Time) {
	r := m.rows[id]
	r.State = state
	if state != app.RequestRequested && r.DeliveredAt.IsZero() {
		r.DeliveredAt = at
	}
}

type stepClock struct{ t time.Time }

func (c *stepClock) Now() time.Time { return c.t }

type closedMem struct {
	cycles []app.RebuildCycle
	err    error
}

func (c *closedMem) CycleClosed(_ context.Context, cy app.RebuildCycle) error {
	c.cycles = append(c.cycles, cy)
	return c.err
}

type decisionRig struct {
	loop     *app.RebuildLoop
	cycles   *cyclesMem
	requests *requestsMem
	posture  *postureMem
	intents  *intentStore
	clock    *stepClock
	closed   *closedMem
}

var errBoom = errors.New("boom")

// rig builds a loop that opens cycles from decisions. routed=true sets a rebuild_requested route
// to the audience "builders"; signed says whether that audience has a signing secret.
func rig(routed, signed bool) *decisionRig {
	cfg := app.DeliveryIntentConfig{RebuildDestination: "team/build-image", SignedAudiences: map[string]bool{"builders": signed}}
	if routed {
		cfg.WebhookRoutes = map[string]string{app.WebhookRebuildRequested: "builders"}
	}
	r := &decisionRig{cycles: newCyclesMem(), requests: newRequestsMem(), posture: &postureMem{}, intents: newIntentStore(),
		clock: &stepClock{t: intentEpoch}, closed: &closedMem{}}
	svc := app.NewDeliveryIntentService(r.intents, &intentIDs{}, r.clock, cfg)
	r.loop = app.NewRebuildLoop(r.cycles, r.posture, svc, r.clock, 2).
		WithDecisions(r.requests, app.RebuildOpenFromDecision).WithCycleClosed(r.closed)
	return r
}

func decision(id string) app.RebuildDecisionFacts {
	return app.RebuildDecisionFacts{DecisionID: id, ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "proj-1",
		TriggerType: "fix_available", CoolDown: time.Hour, CVEs: []string{"CVE-2026-2", "CVE-2026-1", "CVE-2026-2"},
		Raw: []byte(`{"decision_id":"` + id + `"}`)}
}

// open opens a cycle for rel-1 and returns the intent id of its first request.
func (r *decisionRig) open(t *testing.T) string {
	t.Helper()
	out, err := r.loop.Request(context.Background(), lineage(), decision("dec-1"))
	if err != nil || out.State != app.DecisionOpened || !out.Requested {
		t.Fatalf("open = %+v (err %v)", out, err)
	}
	return r.requests.order[len(r.requests.order)-1]
}

// openJoined opens a cycle and lets one more decision join it, so that its closing is told (D21).
func (r *decisionRig) openJoined(t *testing.T) string {
	t.Helper()
	id := r.open(t)
	if out, err := r.loop.Request(context.Background(), lineage(), decision("dec-joined")); err != nil || out.State != app.DecisionJoined {
		t.Fatalf("join = %+v (err %v)", out, err)
	}
	return id
}

// D21, D44 item 7: a cycle opened from a decision always says that it closed, because Governance
// holds new recommendations back until then. A cycle the posture opened says so only when a
// decision joined it: nothing else waits for it.
func TestCycleClosed_WhoIsTold(t *testing.T) {
	ctx := context.Background()
	alone := rig(true, true)
	alone.open(t)
	if _, err := alone.loop.Stop(ctx, "rel-1", "pat", ""); err != nil || len(alone.closed.cycles) != 1 {
		t.Fatalf("a decision cycle must be told once: %d (err %v)", len(alone.closed.cycles), err)
	}
	if ev := app.CycleClosedEvent(alone.closed.cycles[0]); ev.DecisionID != "dec-1" || len(ev.Joined) != 0 {
		t.Errorf("event of a cycle nobody joined = %+v", ev)
	}
	posture := rig(true, true)
	if _, err := posture.cycles.CreateCycle(ctx, app.RebuildCycle{ReleaseID: "rel-9", State: app.CycleOpen, Origin: app.CycleOriginEvaluation}); err != nil {
		t.Fatal(err)
	}
	if _, err := posture.loop.Stop(ctx, "rel-9", "pat", ""); err != nil || len(posture.closed.cycles) != 0 {
		t.Fatalf("a posture cycle nobody joined must not be told: %d (err %v)", len(posture.closed.cycles), err)
	}
	joined := rig(true, true)
	joined.openJoined(t)
	if _, err := joined.loop.Stop(ctx, "rel-1", "pat", ""); err != nil || len(joined.closed.cycles) != 1 {
		t.Fatalf("a joined cycle must be told once: %d (err %v)", len(joined.closed.cycles), err)
	}
	ev := app.CycleClosedEvent(joined.closed.cycles[0])
	if ev.ReleaseID != "rel-1" || ev.State != app.CycleStopped || ev.Origin != app.CycleOriginDecision || ev.DecisionID != "dec-1" ||
		!reflect.DeepEqual(ev.Joined, []string{"dec-joined"}) || ev.ProductID != "prod-1" || ev.ClosedAt.IsZero() {
		t.Errorf("event = %+v", ev)
	}
	if ev := app.CycleClosedEvent(app.RebuildCycle{ID: 1}); ev.Origin != app.CycleOriginEvaluation || ev.Joined == nil {
		t.Errorf("a cycle the posture opened = %+v", ev)
	}
}

func TestRequest_IgnoredWhenNotActedOn(t *testing.T) {
	ctx := context.Background()
	plain, _, _, _ := loopFixture(2)
	if plain.OpensFromDecision() {
		t.Fatal("a loop with no request store must not open from decisions")
	}
	byEvaluation := rig(true, true)
	byEvaluation.loop.WithDecisions(byEvaluation.requests, "anything else")
	if byEvaluation.loop.OpensFromDecision() {
		t.Fatal("an unknown open-from value must mean evaluation")
	}
	noRelease, noDecision, noCVE := decision("d"), decision(""), decision("d")
	noRelease.ReleaseID, noCVE.CVEs = " ", nil
	for name, tc := range map[string]struct {
		loop *app.RebuildLoop
		d    app.RebuildDecisionFacts
	}{
		"no request store": {plain, decision("d")}, "opens from evaluation": {byEvaluation.loop, decision("d")},
		"no release": {rig(true, true).loop, noRelease}, "no decision id": {rig(true, true).loop, noDecision},
		"nothing targeted": {rig(true, true).loop, noCVE},
	} {
		out, err := tc.loop.Request(ctx, lineage(), tc.d)
		if err != nil || out.State != app.DecisionIgnored {
			t.Errorf("%s: %+v (err %v)", name, out, err)
		}
	}
}

// A decision opens a cycle with the frozen decision, the sorted distinct CVEs and the SBOM
// evaluated last, clears a hold, and makes request 1/1 as the signed event.
func TestRequest_OpensACycleAndAsksOverTheRoute(t *testing.T) {
	r := rig(true, true)
	r.requests.sboms["rel-1"] = "sbom-9"
	r.requests.holds["rel-1"] = app.RebuildHold{ReleaseID: "rel-1", Reason: app.HoldCoolDown}
	id := r.open(t)

	cycle := r.cycles.all[0]
	if cycle.Origin != app.CycleOriginDecision || cycle.DecisionID != "dec-1" || cycle.Attempts != 1 || cycle.State != app.CycleOpen ||
		cycle.BaselineSBOMID != "sbom-9" || cycle.LastSBOMID != "sbom-9" || cycle.ProductID != "prod-1" || cycle.ProjectID != "proj-1" ||
		!reflect.DeepEqual(cycle.Targeted, []string{"CVE-2026-1", "CVE-2026-2"}) || string(cycle.Decision) != `{"decision_id":"dec-1"}` {
		t.Fatalf("cycle = %+v", cycle)
	}
	if _, held := r.requests.holds["rel-1"]; held || r.requests.cleared != 1 {
		t.Error("opening a cycle must clear the hold")
	}
	req := *r.requests.rows[id]
	if req.Attempt != 1 || req.Try != 1 || req.Channel != app.ChannelWebhook || req.State != app.RequestRequested ||
		req.CycleID != cycle.ID || req.DecisionID != "dec-1" || req.ReleaseID != "rel-1" || !req.RequestedAt.Equal(intentEpoch) {
		t.Fatalf("request = %+v", req)
	}
	in := r.intents.created[0]
	if in.ID != id || in.Type != app.IntentWebhook || in.Destination != "builders" || in.OriginEventID != "rebuild:1:1:1" ||
		!in.IsRebuildRequest() || in.Snapshot[app.SnapshotRebuildDecision] != `{"decision_id":"dec-1"}` ||
		in.Snapshot[app.SnapshotRebuildCycleID] != "1" || in.Snapshot[app.SnapshotRebuildTry] != "1" || in.Snapshot[app.SnapshotAttempt] != "1" ||
		in.Snapshot[app.SnapshotRebuildMaxAttempts] != "2" || in.Snapshot[app.SnapshotPriorSBOMID] != "sbom-9" ||
		in.Snapshot[app.SnapshotTargetedCVEs] != "CVE-2026-1,CVE-2026-2" || in.ProductID != "prod-1" || in.ReleaseID != "rel-1" {
		t.Fatalf("intent = %+v", in)
	}
}

// With no route the built-in sender is asked (D43): a ci_rebuild intent with the same identity.
func TestRequest_AsksTheBuiltInSenderWithoutARoute(t *testing.T) {
	r := rig(false, false)
	id := r.open(t)
	in := r.intents.created[0]
	if in.Type != app.IntentCIRebuild || in.Destination != "team/build-image" || in.OriginEventID != "rebuild:1:1:1" || !in.IsRebuildRequest() ||
		in.Snapshot[app.SnapshotRebuildDecisionID] != "dec-1" || in.Snapshot[app.SnapshotTargetedCVEs] != "CVE-2026-1,CVE-2026-2" {
		t.Fatalf("intent = %+v", in)
	}
	if r.requests.rows[id].Channel != app.ChannelJenkins {
		t.Errorf("channel = %s", r.requests.rows[id].Channel)
	}
}

// A route with no signing secret sends nothing and opens nothing; the hold says why (D6).
func TestRequest_HeldByAnUnsignedRoute(t *testing.T) {
	r := rig(true, false)
	out, err := r.loop.Request(context.Background(), lineage(), decision("dec-1"))
	if err != nil || out.State != app.DecisionHeld || out.HoldReason != app.HoldUnsignedRoute {
		t.Fatalf("out = %+v (err %v)", out, err)
	}
	if len(r.cycles.all) != 0 || len(r.intents.created) != 0 || r.requests.holds["rel-1"].DecisionID != "dec-1" {
		t.Errorf("an unsigned route must open nothing: cycles %d intents %d holds %v", len(r.cycles.all), len(r.intents.created), r.requests.holds)
	}
}

// The cool-down counts from the last delivered request and gates only a new cycle (D14).
func TestRequest_HeldByTheCoolDownThenOpens(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	id := r.open(t)
	r.requests.set(id, app.RequestDelivered, r.clock.t)
	if _, err := r.loop.Stop(ctx, "rel-1", "pat", "test"); err != nil {
		t.Fatal(err)
	}

	r.clock.t = intentEpoch.Add(30 * time.Minute)
	out, err := r.loop.Request(ctx, lineage(), decision("dec-2"))
	if err != nil || out.State != app.DecisionHeld || out.HoldReason != app.HoldCoolDown {
		t.Fatalf("inside the cool-down: %+v (err %v)", out, err)
	}
	if h := r.requests.holds["rel-1"]; h.DecisionID != "dec-2" || !h.Until.Equal(intentEpoch.Add(time.Hour)) {
		t.Errorf("hold = %+v", h)
	}

	r.clock.t = intentEpoch.Add(61 * time.Minute)
	out, err = r.loop.Request(ctx, lineage(), decision("dec-3"))
	if err != nil || out.State != app.DecisionOpened || len(r.cycles.all) != 2 {
		t.Fatalf("after the cool-down: %+v (err %v)", out, err)
	}
}

// A decision for a Release with an open cycle joins it once, changes no targeted set, and makes
// a refused request again with the next try (D13, D20 item 3, D21, D40).
func TestRequest_JoinsTheOpenCycle(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	id := r.open(t)

	for i := 0; i < 2; i++ { // the same decision twice joins once
		out, err := r.loop.Request(ctx, lineage(), decision("dec-2"))
		if err != nil || out.State != app.DecisionJoined || out.Requested {
			t.Fatalf("join %d = %+v (err %v)", i, out, err)
		}
	}
	if out, _ := r.loop.Request(ctx, lineage(), decision("dec-1")); out.State != app.DecisionJoined {
		t.Fatalf("the opening decision again = %+v", out)
	}
	cycle := *r.cycles.rows["rel-1"]
	if !reflect.DeepEqual(cycle.Joined, []string{"dec-2"}) || len(cycle.Targeted) != 2 || len(r.requests.order) != 1 {
		t.Fatalf("cycle after joins = %+v, requests %v", cycle, r.requests.order)
	}

	r.requests.set(id, app.RequestRefused, r.clock.t)
	out, err := r.loop.Request(ctx, lineage(), decision("dec-3"))
	if err != nil || !out.Requested || len(r.requests.order) != 2 {
		t.Fatalf("join after a refusal = %+v (err %v)", out, err)
	}
	again := *r.requests.rows[r.requests.order[1]]
	if again.Attempt != 1 || again.Try != 2 || again.IntentID == id || r.intents.created[1].OriginEventID != "rebuild:1:1:2" {
		t.Errorf("request made again = %+v", again)
	}
}

// A decision joins a cycle the posture opened too, and asks for nothing there.
func TestRequest_JoinsAnEvaluationCycleWithoutAsking(t *testing.T) {
	r := rig(true, true)
	r.cycles.rows["rel-1"] = &app.RebuildCycle{ID: 7, ReleaseID: "rel-1", State: app.CycleOpen, Attempts: 1, Targeted: []string{"CVE-2026-1"}}
	out, err := r.loop.Request(context.Background(), lineage(), decision("dec-1"))
	if err != nil || out.State != app.DecisionJoined || out.Requested || len(r.intents.created) != 0 {
		t.Fatalf("out = %+v (err %v)", out, err)
	}
}

// In decision mode the posture alone opens nothing, and the SBOM evaluated last is kept.
func TestEvaluate_PostureOpensNothingInDecisionMode(t *testing.T) {
	r := rig(true, true)
	r.posture.rows = rows(map[string]int{"CVE-2026-1": 95})
	out, err := r.loop.Evaluate(context.Background(), "rel-1", "sbom-1", "env-1")
	if err != nil || out.State != app.OutcomeClean || len(r.cycles.all) != 0 || r.requests.sboms["rel-1"] != "sbom-1" {
		t.Fatalf("out = %+v (err %v) sboms %v", out, err, r.requests.sboms)
	}
}

// The attempt advances only when the last request held it (D28): a request on its way is waited
// for; a delivered one is evaluated and the next attempt asked; the limit exhausts the cycle.
func TestEvaluate_DecisionCycleAdvancesOnHeldAttempts(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	first := r.openJoined(t)
	r.posture.rows = rows(map[string]int{"CVE-2026-1": 95, "CVE-2026-2": 80})

	out, err := r.loop.Evaluate(ctx, "rel-1", "sbom-2", "env-2")
	if err != nil || out.State != app.OutcomeContinuing || out.NextAttempt != 0 || out.BaselineSBO != "" || out.PriorSBO != "sbom-2" {
		t.Fatalf("request on its way: %+v (err %v)", out, err)
	}
	if _, raised, _ := r.loop.Raise(ctx, lineage(), "env-2", out, "prod-1", "proj-1"); raised {
		t.Fatal("nothing is asked while a request is on its way")
	}

	r.requests.set(first, app.RequestDelivered, r.clock.t)
	out, err = r.loop.Evaluate(ctx, "rel-1", "sbom-3", "env-3")
	if err != nil || out.State != app.OutcomeContinuing || out.NextAttempt != 2 || r.requests.rows[first].State != app.RequestEvaluated {
		t.Fatalf("delivered then evaluated: %+v (err %v) first=%s", out, err, r.requests.rows[first].State)
	}
	in, raised, err := r.loop.Raise(ctx, lineage(), "env-3", out, "prod-1", "proj-1")
	if err != nil || !raised || in.OriginEventID != "rebuild:1:2:1" || in.Snapshot[app.SnapshotPriorSBOMID] != "sbom-3" {
		t.Fatalf("attempt 2 = %+v raised=%t err=%v", in, raised, err)
	}
	second := in.ID
	if r.requests.rows[second].Attempt != 2 || r.requests.rows[second].Try != 1 {
		t.Fatalf("second request = %+v", r.requests.rows[second])
	}

	// The next ask already exists and is on its way: the default branch, nothing asked.
	if out, _ = r.loop.Evaluate(ctx, "rel-1", "sbom-4", "env-4"); out.NextAttempt != 0 || out.State != app.OutcomeContinuing {
		t.Fatalf("second on its way: %+v", out)
	}

	r.requests.set(second, app.RequestSubmitted, r.clock.t)
	out, err = r.loop.Evaluate(ctx, "rel-1", "sbom-5", "env-5")
	if err != nil || out.State != app.OutcomeExhausted || r.cycles.rows["rel-1"].State != app.CycleExhausted {
		t.Fatalf("limit reached: %+v (err %v)", out, err)
	}
	if len(r.closed.cycles) != 1 || r.closed.cycles[0].State != app.CycleExhausted {
		t.Errorf("a closed cycle must be told once: %+v", r.closed.cycles)
	}
}

func TestEvaluate_DecisionCycleSucceedsWhenTheTargetsClose(t *testing.T) {
	r := rig(true, true)
	first := r.openJoined(t)
	r.requests.set(first, app.RequestBuildReported, r.clock.t)
	r.posture.rows = rows(map[string]int{"CVE-2026-9": 40})
	out, err := r.loop.Evaluate(context.Background(), "rel-1", "sbom-2", "env-2")
	if err != nil || out.State != app.OutcomeSucceeded || r.requests.rows[first].State != app.RequestEvaluated || len(r.closed.cycles) != 1 {
		t.Fatalf("out = %+v (err %v)", out, err)
	}
}

// A refused request is made again by the next evaluation with the same attempt and the next
// try; a cycle with no request at all makes its present attempt.
func TestEvaluate_DecisionCycleAsksAgainAfterARefusal(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	first := r.open(t)
	r.posture.rows = rows(map[string]int{"CVE-2026-1": 95})
	r.requests.set(first, app.RequestRefused, r.clock.t)
	out, _ := r.loop.Evaluate(ctx, "rel-1", "sbom-2", "env-2")
	in, raised, err := r.loop.Raise(ctx, lineage(), "env-2", out, "", "")
	if err != nil || !raised || in.OriginEventID != "rebuild:1:1:2" || r.cycles.rows["rel-1"].Attempts != 1 {
		t.Fatalf("after a refusal: %+v raised=%t err=%v", in, raised, err)
	}

	bare := rig(true, true)
	bare.cycles.rows["rel-1"] = &app.RebuildCycle{ID: 4, ReleaseID: "rel-1", State: app.CycleOpen, Attempts: 1,
		Targeted: []string{"CVE-2026-1"}, Origin: app.CycleOriginDecision, DecisionID: "dec-1"}
	bare.posture.rows = rows(map[string]int{"CVE-2026-1": 95})
	out, _ = bare.loop.Evaluate(ctx, "rel-1", "sbom-2", "env-2")
	if in, raised, _ = bare.loop.Raise(ctx, lineage(), "env-2", out, "", ""); !raised || in.OriginEventID != "rebuild:4:1:1" {
		t.Fatalf("no request yet: %+v raised=%t", in, raised)
	}
}

// When the route loses its secret after a cycle opened, the next ask is held and nothing is sent.
func TestRaise_HeldWhenTheRouteIsUnsigned(t *testing.T) {
	ctx := context.Background()
	r := rig(true, false)
	r.cycles.rows["rel-1"] = &app.RebuildCycle{ID: 4, ReleaseID: "rel-1", State: app.CycleOpen, Attempts: 1,
		Targeted: []string{"CVE-2026-1"}, Origin: app.CycleOriginDecision, DecisionID: "dec-1"}
	r.posture.rows = rows(map[string]int{"CVE-2026-1": 95})
	out, _ := r.loop.Evaluate(ctx, "rel-1", "sbom-2", "env-2")
	_, raised, err := r.loop.Raise(ctx, lineage(), "env-2", out, "", "")
	if err != nil || raised || r.requests.holds["rel-1"].Reason != app.HoldUnsignedRoute || len(r.intents.created) != 0 {
		t.Fatalf("raised=%t err=%v holds=%v", raised, err, r.requests.holds)
	}
	if _, err := r.loop.RequestAgain(ctx, "rel-1", "pat"); !errors.Is(err, app.ErrRebuildHeld) {
		t.Errorf("request again on an unsigned route = %v", err)
	}
}

func TestRecordStatus_Validation(t *testing.T) {
	ctx := context.Background()
	plain, _, _, _ := loopFixture(2)
	if _, err := plain.RecordStatus(ctx, app.RebuildStatus{IntentID: "x", Status: "submitted"}); !errors.Is(err, app.ErrRebuildRequestsUnavailable) {
		t.Errorf("no store = %v", err)
	}
	r := rig(true, true)
	id := r.open(t)
	for want, st := range map[error]app.RebuildStatus{
		app.ErrStatusIncomplete:       {IntentID: " ", Status: "submitted"},
		app.ErrStatusUnknown:          {IntentID: id, Status: "started"},
		app.ErrRebuildRequestNotFound: {IntentID: "nope", Status: "submitted"},
	} {
		if _, err := r.loop.RecordStatus(ctx, st); !errors.Is(err, want) {
			t.Errorf("%+v = %v, want %v", st, err, want)
		}
	}
	r.requests.set(id, app.RequestEvaluated, r.clock.t)
	if _, err := r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: id, Status: "refused"}); !errors.Is(err, app.ErrStatusConflict) {
		t.Errorf("a status on an evaluated request = %v", err)
	}
	r.requests.set(id, app.RequestSubmitted, r.clock.t)
	if _, err := r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: id, Status: "refused"}); !errors.Is(err, app.ErrStatusConflict) {
		t.Errorf("refused after submitted = %v", err)
	}
}

// submitted uses the attempt, keeps the build's identity, and may be said again (D38).
func TestRecordStatus_Submitted(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	id := r.open(t)
	r.clock.t = intentEpoch.Add(time.Minute)
	req, err := r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: " " + id + " ", Status: "submitted", BuildRef: " queue/12 ", ReportedBy: "key:cb"})
	if err != nil || req.State != app.RequestSubmitted || req.BuildRef != "queue/12" || !req.DeliveredAt.Equal(r.clock.t) ||
		!req.StatusAt.Equal(r.clock.t) || req.ReportedBy != "key:cb" || !req.ExecutionStartedAt.IsZero() {
		t.Fatalf("submitted = %+v (err %v)", req, err)
	}
	r.clock.t = intentEpoch.Add(2 * time.Minute)
	req, err = r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: id, Status: "submitted", ExecutionStarted: true})
	if err != nil || req.BuildRef != "queue/12" || !req.ExecutionStartedAt.Equal(r.clock.t) || !req.DeliveredAt.Equal(intentEpoch.Add(time.Minute)) {
		t.Fatalf("submitted again = %+v (err %v)", req, err)
	}
	if len(r.intents.created) != 1 {
		t.Errorf("a submitted status must tell nobody: %d intents", len(r.intents.created))
	}
}

// A refusal is counted on the cycle and told; the third stops the cycle as refused (D20).
func TestRecordStatus_RefusalsStopTheCycle(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	id := r.openJoined(t)
	for n := 1; n <= app.MaxRefusalsPerCycle; n++ {
		r.requests.set(id, app.RequestDelivered, r.clock.t)
		req, err := r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: id, Status: "refused", Reason: " freeze window "})
		if err != nil || req.State != app.RequestRefused || req.Reason != "freeze window" || r.cycles.rows["rel-1"].Refusals != n {
			t.Fatalf("refusal %d = %+v (err %v) cycle %+v", n, req, err, r.cycles.rows["rel-1"])
		}
	}
	cycle := r.cycles.rows["rel-1"]
	if cycle.State != app.CycleRefused || cycle.Attempts != 1 || len(r.closed.cycles) != 1 {
		t.Fatalf("cycle = %+v closed=%d", cycle, len(r.closed.cycles))
	}
	// One notice per request and kind: this request got "refused" once and "cycle_refused" once.
	var kinds []string
	for _, in := range r.intents.created[1:] {
		if !in.IsRebuildNotification() || in.Type != app.IntentEmail || in.ReleaseID != "rel-1" || in.Snapshot[app.SnapshotRebuildIntentID] != id {
			t.Fatalf("notice = %+v", in)
		}
		kinds = append(kinds, in.Snapshot[app.SnapshotRebuildNotice])
	}
	if !reflect.DeepEqual(kinds, []string{app.NoticeRefused, app.NoticeCycleRefused}) {
		t.Errorf("notices = %v", kinds)
	}
	// A refusal that arrives for a cycle already closed changes no counter.
	r.requests.set(id, app.RequestDelivered, r.clock.t)
	if _, err := r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: id, Status: "refused"}); err != nil || cycle.Refusals != 3 {
		t.Errorf("late refusal: err %v refusals %d", err, cycle.Refusals)
	}
}

func TestRecordStatus_UncertainTellsAPersonAndSettles(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	id := r.open(t)
	req, err := r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: id, Status: "uncertain", Reason: "no build found"})
	if err != nil || req.State != app.RequestUncertain || r.intents.created[1].Snapshot[app.SnapshotRebuildNotice] != app.NoticeUncertain {
		t.Fatalf("uncertain = %+v (err %v)", req, err)
	}
	// uncertain may still be resolved by the connector itself.
	if req, err = r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: id, Status: "uncertain"}); err != nil || req.State != app.RequestUncertain {
		t.Fatalf("uncertain again = %+v (err %v)", req, err)
	}

	for want, args := range map[error][3]string{
		app.ErrActorRequired:          {id, "submitted", " "},
		app.ErrSettleAnswer:           {id, "maybe", "pat"},
		app.ErrRebuildRequestNotFound: {"nope", "submitted", "pat"},
	} {
		if _, err := r.loop.Settle(ctx, args[0], args[1], args[2], ""); !errors.Is(err, want) {
			t.Errorf("settle %v = %v, want %v", args, err, want)
		}
	}
	r.clock.t = intentEpoch.Add(time.Hour)
	req, err = r.loop.Settle(ctx, id, "not_submitted", " pat ", " asked the build team ")
	if err != nil || req.State != app.RequestNotSubmitted || req.SettledBy != "pat" || req.SettledAnswer != "not_submitted" ||
		req.SettleNote != "asked the build team" || !req.SettledAt.Equal(r.clock.t) {
		t.Fatalf("settled = %+v (err %v)", req, err)
	}
	if _, err := r.loop.Settle(ctx, id, "submitted", "pat", ""); !errors.Is(err, app.ErrNotUncertain) {
		t.Errorf("settling twice = %v", err)
	}
	plain, _, _, _ := loopFixture(2)
	if _, err := plain.Settle(ctx, id, "submitted", "pat", ""); !errors.Is(err, app.ErrRebuildRequestsUnavailable) {
		t.Errorf("no store = %v", err)
	}

	// not_submitted gave the attempt back: a person makes the request again, try 2.
	again, err := r.loop.RequestAgain(ctx, "rel-1", "pat")
	if err != nil || again.Attempt != 1 || again.Try != 2 || again.State != app.RequestRequested {
		t.Fatalf("request again = %+v (err %v)", again, err)
	}
	if _, err := r.loop.RequestAgain(ctx, "rel-1", "pat"); !errors.Is(err, app.ErrRequestInFlight) {
		t.Errorf("request again while one is on its way = %v", err)
	}
	// submitted keeps the attempt.
	r.requests.set(again.IntentID, app.RequestUncertain, r.clock.t)
	if req, err = r.loop.Settle(ctx, again.IntentID, "submitted", "pat", ""); err != nil || req.State != app.RequestSubmitted {
		t.Fatalf("settled submitted = %+v (err %v)", req, err)
	}
}

func TestRequestAgain_Refusals(t *testing.T) {
	ctx := context.Background()
	plain, _, _, _ := loopFixture(2)
	if _, err := plain.RequestAgain(ctx, "rel-1", "pat"); !errors.Is(err, app.ErrRebuildRequestsUnavailable) {
		t.Errorf("no store = %v", err)
	}
	r := rig(true, true)
	if _, err := r.loop.RequestAgain(ctx, "rel-1", " "); !errors.Is(err, app.ErrActorRequired) {
		t.Errorf("no actor = %v", err)
	}
	if _, err := r.loop.RequestAgain(ctx, "rel-1", "pat"); !errors.Is(err, app.ErrNoOpenCycle) {
		t.Errorf("no cycle = %v", err)
	}
	r.cycles.rows["rel-1"] = &app.RebuildCycle{ID: 3, ReleaseID: "rel-1", State: app.CycleOpen, Attempts: 1}
	if _, err := r.loop.RequestAgain(ctx, "rel-1", "pat"); !errors.Is(err, app.ErrNoOpenCycle) {
		t.Errorf("a cycle the posture opened = %v", err)
	}
	// An evaluated request of an earlier attempt, with the next attempt never asked: ask it.
	r.cycles.rows["rel-1"] = &app.RebuildCycle{ID: 3, ReleaseID: "rel-1", State: app.CycleOpen, Attempts: 2, Origin: app.CycleOriginDecision}
	r.requests.rows["old"] = &app.RebuildRequest{IntentID: "old", CycleID: 3, ReleaseID: "rel-1", Attempt: 1, Try: 1, State: app.RequestEvaluated}
	r.requests.order = append(r.requests.order, "old")
	req, err := r.loop.RequestAgain(ctx, "rel-1", "pat")
	if err != nil || req.Attempt != 2 || req.Try != 1 {
		t.Fatalf("after an evaluated attempt = %+v (err %v)", req, err)
	}
	// The evaluated request IS the present attempt: nothing is waiting to be asked.
	r.requests.set(req.IntentID, app.RequestEvaluated, r.clock.t)
	if _, err := r.loop.RequestAgain(ctx, "rel-1", "pat"); !errors.Is(err, app.ErrRequestInFlight) {
		t.Errorf("nothing waiting = %v", err)
	}
}

func TestStop(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	if _, err := r.loop.Stop(ctx, "rel-1", "", ""); !errors.Is(err, app.ErrActorRequired) {
		t.Errorf("no actor = %v", err)
	}
	if _, err := r.loop.Stop(ctx, "rel-1", "pat", ""); !errors.Is(err, app.ErrNoOpenCycle) {
		t.Errorf("no cycle = %v", err)
	}
	r.openJoined(t)
	cycle, err := r.loop.Stop(ctx, "rel-1", " pat ", " mode is off now ")
	if err != nil || cycle.State != app.CycleStopped || cycle.ClosedBy != "pat" || cycle.ClosedNote != "mode is off now" || len(r.closed.cycles) != 1 {
		t.Fatalf("stopped = %+v (err %v)", cycle, err)
	}
}

func TestBuildReported(t *testing.T) {
	ctx := context.Background()
	plain, _, _, _ := loopFixture(2)
	if err := plain.BuildReported(ctx, "x"); err != nil {
		t.Errorf("no store = %v", err)
	}
	r := rig(true, true)
	if err := r.loop.BuildReported(ctx, "an intent of the old loop"); err != nil {
		t.Errorf("no request row = %v", err)
	}
	id := r.open(t)
	r.clock.t = intentEpoch.Add(time.Minute)
	if err := r.loop.BuildReported(ctx, id); err != nil || r.requests.rows[id].State != app.RequestBuildReported || !r.requests.rows[id].DeliveredAt.Equal(r.clock.t) {
		t.Fatalf("reported = %+v (err %v)", r.requests.rows[id], err)
	}
	r.requests.set(id, app.RequestRefused, r.clock.t)
	if err := r.loop.BuildReported(ctx, id); err != nil || r.requests.rows[id].State != app.RequestRefused {
		t.Errorf("a refused request must stay refused: %+v (err %v)", r.requests.rows[id], err)
	}
	r.requests.fail["RequestByIntent"] = errBoom
	if err := r.loop.BuildReported(ctx, id); !errors.Is(err, errBoom) {
		t.Errorf("store failure = %v", err)
	}
}

// A delivered request nobody reported on for a day becomes uncertain and a person is told (D28).
func TestSweepSilent(t *testing.T) {
	ctx := context.Background()
	plain, _, _, _ := loopFixture(2)
	if n, err := plain.SweepSilent(ctx); n != 0 || err != nil {
		t.Errorf("no store = %d %v", n, err)
	}
	r := rig(true, true)
	id := r.open(t)
	r.requests.set(id, app.RequestDelivered, intentEpoch)
	r.clock.t = intentEpoch.Add(23 * time.Hour)
	if n, _ := r.loop.SweepSilent(ctx); n != 0 {
		t.Fatalf("before the limit: %d", n)
	}
	r.clock.t = intentEpoch.Add(25 * time.Hour)
	n, err := r.loop.SweepSilent(ctx)
	req := r.requests.rows[id]
	if err != nil || n != 1 || req.State != app.RequestUncertain || req.Reason == "" || r.intents.created[1].Snapshot[app.SnapshotRebuildNotice] != app.NoticeUncertain {
		t.Fatalf("sweep = %d (err %v) %+v", n, err, req)
	}
	if n, _ = r.loop.SweepSilent(ctx); n != 0 {
		t.Errorf("a second pass finds nothing: %d", n)
	}
}

func TestViewAndProductOfRequest(t *testing.T) {
	ctx := context.Background()
	plain, _, _, _ := loopFixture(2)
	if _, err := plain.View(ctx, "rel-1"); !errors.Is(err, app.ErrRebuildRequestsUnavailable) {
		t.Errorf("view, no store = %v", err)
	}
	if _, err := plain.ProductOfRequest(ctx, "x"); !errors.Is(err, app.ErrRebuildRequestsUnavailable) {
		t.Errorf("product, no store = %v", err)
	}
	r := rig(true, true)
	view, err := r.loop.View(ctx, "rel-1")
	if err != nil || view.Cycle != nil || view.Hold != nil || len(view.Requests) != 0 {
		t.Fatalf("empty view = %+v (err %v)", view, err)
	}
	id := r.open(t)
	r.requests.holds["rel-1"] = app.RebuildHold{ReleaseID: "rel-1", DecisionID: "dec-9", Reason: app.HoldCoolDown}
	view, err = r.loop.View(ctx, "rel-1")
	if err != nil || view.Cycle == nil || view.Cycle.DecisionID != "dec-1" || len(view.Requests) != 1 || view.Hold == nil || view.Hold.DecisionID != "dec-9" {
		t.Fatalf("view = %+v (err %v)", view, err)
	}
	if p, err := r.loop.ProductOfRequest(ctx, " "+id+" "); err != nil || p != "prod-1" {
		t.Errorf("product = %q (err %v)", p, err)
	}
	if _, err := r.loop.ProductOfRequest(ctx, "nope"); !errors.Is(err, app.ErrRebuildRequestNotFound) {
		t.Errorf("unknown request = %v", err)
	}
}

// Every store failure is returned, never swallowed: the event is then retried by the bus, or
// the caller is told.
func TestRebuildRequests_StoreFailuresAreReturned(t *testing.T) {
	ctx := context.Background()
	type step func(r *decisionRig) error
	request := func(r *decisionRig) error {
		_, err := r.loop.Request(ctx, lineage(), decision("dec-2"))
		return err
	}
	evaluate := func(r *decisionRig) error {
		r.posture.rows = rows(map[string]int{"CVE-2026-1": 95})
		_, err := r.loop.Evaluate(ctx, "rel-1", "sbom-2", "env-2")
		return err
	}
	status := func(s string) step {
		return func(r *decisionRig) error {
			_, err := r.loop.RecordStatus(ctx, app.RebuildStatus{IntentID: r.requests.order[0], Status: s})
			return err
		}
	}
	cases := []struct {
		name   string
		opens  bool // open a cycle first
		state  string
		break_ func(r *decisionRig)
		run    step
	}{
		{"request: open cycle read", false, "", func(r *decisionRig) { r.cycles.openErr = errBoom }, request},
		{"request: last delivered", false, "", func(r *decisionRig) { r.requests.fail["LastDeliveredAt"] = errBoom }, request},
		{"request: last sbom", false, "", func(r *decisionRig) { r.requests.fail["LastSBOM"] = errBoom }, request},
		{"request: create cycle", false, "", func(r *decisionRig) { r.cycles.createErr = errBoom }, request},
		{"request: clear hold", false, "", func(r *decisionRig) { r.requests.fail["ClearHold"] = errBoom }, request},
		{"request: enqueue", false, "", func(r *decisionRig) { r.intents.err = errBoom }, request},
		{"request: create request", false, "", func(r *decisionRig) { r.requests.fail["CreateRequest"] = errBoom }, request},
		{"join: update cycle", true, "", func(r *decisionRig) { r.cycles.updateErr = errBoom }, request},
		{"join: latest request", true, "", func(r *decisionRig) { r.requests.fail["LatestRequest"] = errBoom }, request},
		{"evaluate: save last sbom", true, "", func(r *decisionRig) { r.requests.fail["SaveLastSBOM"] = errBoom }, evaluate},
		{"evaluate: latest request", true, "", func(r *decisionRig) { r.requests.fail["LatestRequest"] = errBoom }, evaluate},
		{"evaluate: update request", true, app.RequestDelivered, func(r *decisionRig) { r.requests.fail["UpdateRequest"] = errBoom }, evaluate},
		{"evaluate: update cycle", true, "", func(r *decisionRig) { r.cycles.updateErr = errBoom }, evaluate},
		{"status: update request", true, "", func(r *decisionRig) { r.requests.fail["UpdateRequest"] = errBoom }, status("submitted")},
		{"status: cycle read", true, "", func(r *decisionRig) { r.cycles.byIDErr = errBoom }, status("refused")},
		{"status: update cycle", true, "", func(r *decisionRig) { r.cycles.updateErr = errBoom }, status("refused")},
		{"status: refusal notice", true, "", func(r *decisionRig) { r.intents.err = errBoom }, status("refused")},
		{"status: uncertain notice", true, "", func(r *decisionRig) { r.intents.err = errBoom }, status("uncertain")},
		{"again: open cycle read", true, "", func(r *decisionRig) { r.cycles.openErr = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.RequestAgain(ctx, "rel-1", "pat")
			return err
		}},
		{"again: latest request", true, "", func(r *decisionRig) { r.requests.fail["LatestRequest"] = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.RequestAgain(ctx, "rel-1", "pat")
			return err
		}},
		{"again: enqueue", true, app.RequestRefused, func(r *decisionRig) { r.intents.err = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.RequestAgain(ctx, "rel-1", "pat")
			return err
		}},
		{"stop: open cycle read", true, "", func(r *decisionRig) { r.cycles.openErr = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.Stop(ctx, "rel-1", "pat", "")
			return err
		}},
		{"stop: update cycle", true, "", func(r *decisionRig) { r.cycles.updateErr = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.Stop(ctx, "rel-1", "pat", "")
			return err
		}},
		{"stop: closed notifier", true, "", func(r *decisionRig) {
			_, _ = r.loop.Request(ctx, lineage(), decision("dec-joined"))
			r.closed.err = errBoom
		}, func(r *decisionRig) error {
			_, err := r.loop.Stop(ctx, "rel-1", "pat", "")
			return err
		}},
		{"sweep: read", true, "", func(r *decisionRig) { r.requests.fail["SilentRequests"] = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.SweepSilent(ctx)
			return err
		}},
		{"sweep: update", true, app.RequestDelivered, func(r *decisionRig) {
			r.clock.t = intentEpoch.Add(48 * time.Hour)
			r.requests.fail["UpdateRequest"] = errBoom
		}, func(r *decisionRig) error {
			_, err := r.loop.SweepSilent(ctx)
			return err
		}},
		{"sweep: notice", true, app.RequestDelivered, func(r *decisionRig) {
			r.clock.t = intentEpoch.Add(48 * time.Hour)
			r.intents.err = errBoom
		}, func(r *decisionRig) error {
			_, err := r.loop.SweepSilent(ctx)
			return err
		}},
		{"view: latest cycle", true, "", func(r *decisionRig) { r.cycles.latestErr = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.View(ctx, "rel-1")
			return err
		}},
		{"view: requests", true, "", func(r *decisionRig) { r.requests.fail["ListRequests"] = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.View(ctx, "rel-1")
			return err
		}},
		{"view: hold", true, "", func(r *decisionRig) { r.requests.fail["Hold"] = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.View(ctx, "rel-1")
			return err
		}},
		{"product: cycle read", true, "", func(r *decisionRig) { r.cycles.byIDErr = errBoom }, func(r *decisionRig) error {
			_, err := r.loop.ProductOfRequest(ctx, r.requests.order[0])
			return err
		}},
	}
	for _, tc := range cases {
		r := rig(true, true)
		if tc.opens {
			id := r.open(t)
			if tc.state != "" {
				r.requests.set(id, tc.state, intentEpoch)
			}
		}
		tc.break_(r)
		if err := tc.run(r); !errors.Is(err, errBoom) {
			t.Errorf("%s: err = %v, want the store failure", tc.name, err)
		}
	}

	// A hold that cannot be saved is a failure too, on both paths that hold.
	unsigned := rig(true, false)
	unsigned.requests.fail["SaveHold"] = errBoom
	if _, err := unsigned.loop.Request(ctx, lineage(), decision("dec-1")); !errors.Is(err, errBoom) {
		t.Errorf("hold on request = %v", err)
	}
	unsigned.cycles.rows["rel-1"] = &app.RebuildCycle{ID: 4, ReleaseID: "rel-1", State: app.CycleOpen, Attempts: 1, Origin: app.CycleOriginDecision}
	if _, err := unsigned.loop.RequestAgain(ctx, "rel-1", "pat"); !errors.Is(err, errBoom) {
		t.Errorf("hold on ask = %v", err)
	}
}

func TestRebuildChannelAndRequestIntent(t *testing.T) {
	ctx := context.Background()
	for want, r := range map[string]*decisionRig{app.ChannelJenkins: rig(false, false), app.ChannelUnsigned: rig(true, false), app.ChannelWebhook: rig(true, true)} {
		svc := app.NewDeliveryIntentService(r.intents, &intentIDs{}, r.clock, app.DeliveryIntentConfig{})
		_ = svc
		if got := channelOf(r); got != want {
			t.Errorf("channel = %s, want %s", got, want)
		}
	}
	svc := intentSvc(newIntentStore(), app.DeliveryIntentConfig{WebhookRoutes: map[string]string{app.WebhookRebuildRequested: "builders"}})
	if _, _, err := svc.EnqueueRebuildRequest(ctx, lineage(), app.RebuildCycle{ID: 1}, 1, 1, 2); !errors.Is(err, app.ErrNoSubject) {
		t.Errorf("no release = %v", err)
	}
	if _, _, err := svc.EnqueueRebuildRequest(ctx, lineage(), app.RebuildCycle{ID: 1, ReleaseID: "rel-1"}, 1, 1, 2); !errors.Is(err, app.ErrUnsignedRebuildRoute) {
		t.Errorf("unsigned route = %v", err)
	}
	for _, req := range []app.RebuildRequest{{IntentID: "i"}, {ReleaseID: "rel-1"}} {
		if _, err := svc.EnqueueRebuildNotice(ctx, req, app.NoticeRefused); !errors.Is(err, app.ErrNoSubject) {
			t.Errorf("notice for %+v = %v", req, err)
		}
	}
}

// channelOf reads the channel a rig would use through the only public way: opening a cycle.
func channelOf(r *decisionRig) string {
	out, _ := r.loop.Request(context.Background(), lineage(), decision("dec-1"))
	if out.State == app.DecisionHeld {
		return app.ChannelUnsigned
	}
	return r.requests.rows[r.requests.order[0]].Channel
}

// The build callback is accepted for the signed event's intent as it is for the built-in sender's.
func TestRebuildCallback_AcceptsTheRouteIntent(t *testing.T) {
	ctx := context.Background()
	r := rig(true, true)
	id := r.open(t)
	svc := app.NewDeliveryIntentService(r.intents, &intentIDs{}, r.clock, app.DeliveryIntentConfig{}).WithRebuildCallbacks(&cbStore{})
	if _, err := svc.RecordRebuildCallback(ctx, app.RebuildCallback{IntentID: id, SBOMID: "sbom-2", ImageDigest: "sha256:abc"}); err != nil {
		t.Fatalf("callback for a rebuild_requested intent = %v", err)
	}
}
