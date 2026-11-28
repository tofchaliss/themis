package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// --- the trigger worker and the standing recommendation (D41, D44) ---------------------

// firstRecommendation runs one trigger in mode ask with nothing standing and returns the
// recommendation it made, as the store would hold it.
func firstRecommendation(t *testing.T) app.RebuildRecommendation {
	t.Helper()
	st := &triggerStore{pending: oneTrigger(time.Minute)}
	if n := triggerWorker(t, st, domain.RebuildModeAsk, []string{"rebuild:auto"}, rebuildFixVerdicts(), nil).Tick(context.Background()); n != 1 {
		t.Fatalf("settled %d", n)
	}
	got := st.settled[0]
	if got.decision == nil || got.res.Outcome != domain.RebuildOutcomeRecommend || got.res.EndStanding != "" || got.decision.Supersedes != "" {
		t.Fatalf("first recommendation = %+v %+v", got.res, got.decision)
	}
	return app.RebuildRecommendation{Decision: *got.decision, State: domain.RebuildRecStanding, StateAt: triggerNow}
}

func tickOnce(t *testing.T, st *triggerStore, mode domain.RebuildMode) settled {
	t.Helper()
	st.pending = oneTrigger(time.Minute)
	if n := triggerWorker(t, st, mode, []string{"rebuild:auto"}, rebuildFixVerdicts(), nil).Tick(context.Background()); n != 1 || len(st.settled) != 1 {
		t.Fatalf("settled %d %+v", n, st.settled)
	}
	return st.settled[0]
}

// D41 item 2: the same ask as the standing recommendation records no decision and no event.
func TestRebuildTriggerUnchangedAgainstTheStandingRecommendation(t *testing.T) {
	standing := firstRecommendation(t)
	standing.Decision.DecisionID = "dec-standing"
	got := tickOnce(t, &triggerStore{status: app.RebuildRecommendationStatus{Standing: &standing}}, domain.RebuildModeAsk)
	if got.decision != nil || got.note.EventType != "" || got.res.Outcome != domain.RebuildOutcomeUnchanged ||
		got.res.PointsTo != "dec-standing" || got.res.EndStanding != "" || got.res.EndState != "" {
		t.Fatalf("unchanged = %+v decision %+v", got.res, got.decision)
	}
}

// D41 item 3, D45 item 4: a different ask supersedes the standing one and names it.
func TestRebuildTriggerSupersedesADifferentRecommendation(t *testing.T) {
	standing := firstRecommendation(t)
	standing.Decision.DecisionID = "dec-old"
	standing.Decision.Targeted = standing.Decision.Targeted[:1]
	got := tickOnce(t, &triggerStore{status: app.RebuildRecommendationStatus{Standing: &standing}}, domain.RebuildModeAsk)
	if got.decision == nil || got.decision.Supersedes != "dec-old" || got.res.Outcome != domain.RebuildOutcomeRecommend ||
		got.res.EndStanding != "dec-old" || got.res.EndState != domain.RebuildRecSuperseded || got.note.EventType != app.EventRebuildRecommended {
		t.Fatalf("supersede = %+v decision %+v", got.res, got.decision)
	}
}

// D44 item 3: nothing to ask for, or mode auto, withdraws the standing recommendation.
func TestRebuildTriggerWithdrawsTheStandingRecommendation(t *testing.T) {
	standing := firstRecommendation(t)
	standing.Decision.DecisionID = "dec-old"
	off := tickOnce(t, &triggerStore{status: app.RebuildRecommendationStatus{Standing: &standing}}, domain.RebuildModeOff)
	if off.decision != nil || off.res.Outcome != domain.RebuildOutcomeNone || off.res.EndStanding != "dec-old" || off.res.EndState != domain.RebuildRecWithdrawn {
		t.Fatalf("mode off = %+v", off.res)
	}
	auto := tickOnce(t, &triggerStore{status: app.RebuildRecommendationStatus{Standing: &standing}}, domain.RebuildModeAuto)
	if auto.decision == nil || auto.res.Outcome != domain.RebuildOutcomeRequest || auto.res.EndStanding != "dec-old" ||
		auto.res.EndState != domain.RebuildRecWithdrawn || auto.note.EventType != app.EventRebuildRequested || auto.decision.Supersedes != "" {
		t.Fatalf("mode auto = %+v decision %+v", auto.res, auto.decision)
	}
}

// D44 items 1 and 2: a standing recommendation past its 7 days is expired first, with its
// event, and the trigger then makes a new recommendation even for the same ask.
func TestRebuildTriggerExpiresAnOldStandingRecommendationFirst(t *testing.T) {
	standing := firstRecommendation(t)
	standing.Decision.DecisionID = "dec-old"
	standing.Decision.DecidedAt = triggerNow.Add(-domain.RebuildRecommendationTTL)
	st := &triggerStore{status: app.RebuildRecommendationStatus{Standing: &standing}}
	got := tickOnce(t, st, domain.RebuildModeAsk)
	if len(st.expired) != 1 || st.expired[0].EventType != app.EventRebuildRecommendationExpired {
		t.Fatalf("expired = %+v", st.expired)
	}
	ev, ok := st.expired[0].Event.(domain.RebuildRecommendationExpiredEvent)
	if !ok || ev.DecisionID != "dec-old" || ev.ReleaseID != "rel-1" || ev.TargetedCount != 2 || !ev.ExpiredAt.Equal(triggerNow) {
		t.Errorf("expiry event = %+v", st.expired[0].Event)
	}
	if got.decision == nil || got.decision.Supersedes != "" || got.res.EndStanding != "" || got.res.Outcome != domain.RebuildOutcomeRecommend {
		t.Fatalf("after expiry = %+v decision %+v", got.res, got.decision)
	}
	// An expiry that cannot be recorded keeps the trigger open.
	failing := &triggerStore{status: app.RebuildRecommendationStatus{Standing: &standing}, expireErr: errors.New("db down"), pending: oneTrigger(time.Minute)}
	if n := triggerWorker(t, failing, domain.RebuildModeAsk, []string{"rebuild:auto"}, rebuildFixVerdicts(), &triggerLog{}).Tick(context.Background()); n != 0 || len(failing.settled) != 0 {
		t.Errorf("expiry fault: settled %d", n)
	}
	unread := &triggerStore{statusErr: errors.New("db down"), pending: oneTrigger(time.Minute)}
	if n := triggerWorker(t, unread, domain.RebuildModeAsk, []string{"rebuild:auto"}, rebuildFixVerdicts(), &triggerLog{}).Tick(context.Background()); n != 0 || len(unread.settled) != 0 {
		t.Errorf("status fault: settled %d", n)
	}
}

// D44 item 7: after an approval, and until its cycle is known closed, a trigger makes no new
// recommendation and is kept for the closure. The hold has an end of its own.
func TestRebuildTriggerWaitsForTheCycleOfAnApprovedRecommendation(t *testing.T) {
	approved := firstRecommendation(t)
	approved.Decision.DecisionID, approved.State = "dec-approved", domain.RebuildRecApproved
	approved.Approval = &domain.RebuildApproval{Actor: "pat", ApprovedAt: triggerNow.Add(-time.Hour)}
	held := tickOnce(t, &triggerStore{status: app.RebuildRecommendationStatus{ApprovedOpen: &approved}}, domain.RebuildModeAsk)
	if held.decision != nil || held.res.Outcome != domain.RebuildOutcomeNone || held.res.Reason != domain.RebuildNoneCycleOpen || held.res.Retrigger != "dec-approved" {
		t.Fatalf("held = %+v", held.res)
	}
	// Mode auto is not held: its request joins the open cycle on the Communication side.
	auto := tickOnce(t, &triggerStore{status: app.RebuildRecommendationStatus{ApprovedOpen: &approved}}, domain.RebuildModeAuto)
	if auto.decision == nil || auto.res.Outcome != domain.RebuildOutcomeRequest || auto.res.Retrigger != "" {
		t.Fatalf("auto while held = %+v", auto.res)
	}
	approved.Approval.ApprovedAt = triggerNow.Add(-domain.RebuildApprovedHold)
	late := tickOnce(t, &triggerStore{status: app.RebuildRecommendationStatus{ApprovedOpen: &approved}}, domain.RebuildModeAsk)
	if late.decision == nil || late.res.Outcome != domain.RebuildOutcomeRecommend || late.res.Retrigger != "" {
		t.Fatalf("after the hold = %+v", late.res)
	}
}

// --- the approval (D15, D22, D45, D46) --------------------------------------------------

type approvalStore struct {
	recs      map[string]app.RebuildRecommendation
	status    app.RebuildRecommendationStatus
	writes    []app.RebuildApprovalWrite
	results   []string // one per write; the last repeats
	expired   []string
	before    time.Time
	getErr    error
	statusErr error
	writeErr  error
	expireErr error
	listErr   error
	notMoved  bool
}

func (s *approvalStore) RebuildRecommendation(_ context.Context, id string) (app.RebuildRecommendation, bool, error) {
	rec, ok := s.recs[id]
	return rec, ok, s.getErr
}

func (s *approvalStore) LatestRebuildRecommendation(_ context.Context, releaseID string) (app.RebuildRecommendation, bool, error) {
	for _, rec := range s.recs {
		if rec.Decision.ReleaseID == releaseID {
			return rec, true, s.getErr
		}
	}
	return app.RebuildRecommendation{}, false, s.getErr
}

func (s *approvalStore) RebuildRecommendationStatus(context.Context, string) (app.RebuildRecommendationStatus, error) {
	return s.status, s.statusErr
}

func (s *approvalStore) ApproveRebuildRecommendation(_ context.Context, in app.RebuildApprovalWrite) (string, error) {
	if s.writeErr != nil {
		return "", s.writeErr
	}
	s.writes = append(s.writes, in)
	i := len(s.writes) - 1
	if i >= len(s.results) {
		i = len(s.results) - 1
	}
	return s.results[i], nil
}

func (s *approvalStore) StandingRebuildRecommendationsBefore(_ context.Context, before time.Time, _ int) ([]app.RebuildRecommendation, error) {
	s.before = before
	var out []app.RebuildRecommendation
	for _, id := range []string{"dec-1", "dec-2"} {
		if rec, ok := s.recs[id]; ok {
			out = append(out, rec)
		}
	}
	return out, s.listErr
}

func (s *approvalStore) ExpireRebuildRecommendation(_ context.Context, id string, _ time.Time, note app.OutboxNote) (bool, error) {
	if s.expireErr != nil {
		return false, s.expireErr
	}
	if _, ok := note.Event.(domain.RebuildRecommendationExpiredEvent); !ok || note.EventType != app.EventRebuildRecommendationExpired {
		return false, errors.New("the expiry must carry its event")
	}
	s.expired = append(s.expired, id)
	return !s.notMoved, nil
}

type approvalIDs struct{}

func (approvalIDs) NewID() string { return "trig-1" }

func approvalRig(t *testing.T, mode domain.RebuildMode, tags app.ReleaseTagReader, results ...string) (*app.RebuildApprovalService, *approvalStore) {
	t.Helper()
	rec := firstRecommendation(t)
	rec.Decision.DecidedAt = triggerNow.Add(-time.Hour)
	st := &approvalStore{recs: map[string]app.RebuildRecommendation{"dec-1": rec}, results: results}
	policy := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{})
	if tags != nil {
		policy = policy.WithTags(tags)
	} else {
		policy = policy.WithIdentity(nil)
	}
	if _, err := policy.PutInstallation(context.Background(), policyWith(mode, domain.SLABucketHigh), "alice"); err != nil {
		t.Fatal(err)
	}
	return app.NewRebuildApprovalService(st, policy, approvalIDs{}, rebuildClock{triggerNow}), st
}

var approvalKey = app.RebuildApprovalKey{Name: "deciders", Scopes: []string{"product:prod-1"}}

func TestRebuildApprovalPublishesTheFrozenRequest(t *testing.T) {
	svc, st := approvalRig(t, domain.RebuildModeAsk, taggedRelease("rebuild:auto"), app.RebuildApprovalApproved)
	ans, err := svc.Approve(context.Background(), " dec-1 ", " pat ", approvalKey)
	if err != nil || ans.Result != app.RebuildApprovalApproved || ans.State != domain.RebuildRecApproved ||
		ans.DecisionID != "dec-1" || ans.ReleaseID != "rel-1" || ans.EffectiveMode != "ask" {
		t.Fatalf("answer = %+v (err %v)", ans, err)
	}
	if len(st.writes) != 1 {
		t.Fatalf("writes = %d", len(st.writes))
	}
	w := st.writes[0]
	a := w.Approval
	if !w.Approve || w.Expected != (domain.RebuildPolicyVersions{Installation: 1}) || w.TriggerID != "trig-1" || !w.Now.Equal(triggerNow) ||
		a.Actor != "pat" || a.KeyName != "deciders" || len(a.KeyScopes) != 1 || a.PolicyVersions != w.Expected ||
		a.Tag != domain.RebuildTagAuto || a.TagLevel != domain.RebuildTagLevelRelease || !a.ApprovedAt.Equal(triggerNow) || !a.TagsReadAt.Equal(triggerNow) {
		t.Fatalf("write = %+v", w)
	}
	// D27, D46 item 10: the request is the recommendation's own facts, outcome request, with
	// the approval. The decision id does not change.
	req, ok := w.Request.Event.(domain.RebuildDecision)
	if !ok || w.Request.EventType != app.EventRebuildRequested || req.DecisionID != "dec-1" || req.Outcome != domain.RebuildOutcomeRequest ||
		req.RecommendReason != "" || req.Approval == nil || req.Approval.Actor != "pat" || len(req.Targeted) != 2 || req.BuildProfile == nil {
		t.Fatalf("request = %+v", w.Request)
	}
	if st.recs["dec-1"].Decision.Approval != nil || st.recs["dec-1"].Decision.Outcome != domain.RebuildOutcomeRecommend {
		t.Error("the stored recommendation must not be changed by building the request")
	}
}

// D45 items 1 and 2: with the mode no longer ask the recommendation is withdrawn and a trigger
// is recorded; the call starts nothing.
func TestRebuildApprovalWithdrawsWhenTheModeIsNotAsk(t *testing.T) {
	for _, mode := range []domain.RebuildMode{domain.RebuildModeAuto, domain.RebuildModeOff} {
		svc, st := approvalRig(t, mode, taggedRelease("rebuild:auto"), app.RebuildApprovalWithdrawn)
		ans, err := svc.Approve(context.Background(), "dec-1", "pat", approvalKey)
		if err != nil || ans.Result != app.RebuildApprovalWithdrawn || ans.State != domain.RebuildRecWithdrawn || ans.EffectiveMode != string(mode) {
			t.Fatalf("%s: answer = %+v (err %v)", mode, ans, err)
		}
		if len(st.writes) != 1 || st.writes[0].Approve {
			t.Fatalf("%s: writes = %+v", mode, st.writes)
		}
	}
}

// D46 item 1: expiry comes first, whatever the mode, and is recorded with its event.
func TestRebuildApprovalOfAnExpiredRecommendation(t *testing.T) {
	svc, st := approvalRig(t, domain.RebuildModeAuto, taggedRelease("rebuild:auto"))
	rec := st.recs["dec-1"]
	rec.Decision.DecidedAt = triggerNow.Add(-domain.RebuildRecommendationTTL)
	st.recs["dec-1"] = rec
	ans, err := svc.Approve(context.Background(), "dec-1", "pat", approvalKey)
	if err != nil || ans.Result != app.RebuildApprovalExpired || ans.State != domain.RebuildRecExpired || len(st.expired) != 1 || len(st.writes) != 0 {
		t.Fatalf("answer = %+v (err %v) expired %v writes %d", ans, err, st.expired, len(st.writes))
	}
	st.expireErr = errors.New("db down")
	if _, err := svc.Approve(context.Background(), "dec-1", "pat", approvalKey); err == nil {
		t.Error("an expiry that cannot be recorded must be an error")
	}
	// The store sees the expiry under its lock (the clock passed between read and write).
	late, lst := approvalRig(t, domain.RebuildModeAsk, taggedRelease("rebuild:auto"), app.RebuildApprovalExpired)
	if ans, err := late.Approve(context.Background(), "dec-1", "pat", approvalKey); err != nil || ans.Result != app.RebuildApprovalExpired ||
		ans.State != domain.RebuildRecExpired || len(lst.writes) != 1 {
		t.Fatalf("late expiry = %+v (err %v)", ans, err)
	}
}

// D41 item 4: only the standing recommendation can be approved; the answer names the one that is.
func TestRebuildApprovalOfARecommendationThatIsNotStanding(t *testing.T) {
	svc, st := approvalRig(t, domain.RebuildModeAsk, taggedRelease("rebuild:auto"), app.RebuildApprovalNotStanding)
	old := st.recs["dec-1"]
	old.State, old.Decision.DecisionID = domain.RebuildRecSuperseded, "dec-old"
	st.recs["dec-old"] = old
	standing := st.recs["dec-1"]
	st.status.Standing = &standing
	ans, err := svc.Approve(context.Background(), "dec-old", "pat", approvalKey)
	if err != nil || ans.Result != app.RebuildApprovalNotStanding || ans.StandingID != "dec-1" || len(st.writes) != 0 {
		t.Fatalf("answer = %+v (err %v)", ans, err)
	}
	// Lost to another approval at the same moment: the write says so.
	if ans, err := svc.Approve(context.Background(), "dec-1", "pat", approvalKey); err != nil || ans.Result != app.RebuildApprovalNotStanding || len(st.writes) != 1 {
		t.Fatalf("lost race = %+v (err %v)", ans, err)
	}
	// A standing one past its time is not offered as the one to approve.
	standing.Decision.DecidedAt = triggerNow.Add(-domain.RebuildRecommendationTTL)
	if ans, _ := svc.Approve(context.Background(), "dec-old", "pat", approvalKey); ans.StandingID != "" {
		t.Errorf("an expired standing recommendation was offered: %+v", ans)
	}
	st.status.Standing = nil
	if ans, _ := svc.Approve(context.Background(), "dec-old", "pat", approvalKey); ans.StandingID != "" || ans.State != domain.RebuildRecSuperseded {
		t.Errorf("nothing standing = %+v", ans)
	}
	st.statusErr = errors.New("db down")
	if _, err := svc.Approve(context.Background(), "dec-old", "pat", approvalKey); err == nil {
		t.Error("a status fault must be an error")
	}
}

func TestRebuildApprovalRefusals(t *testing.T) {
	ctx := context.Background()
	svc, st := approvalRig(t, domain.RebuildModeAsk, taggedRelease("rebuild:auto"), app.RebuildApprovalApproved)
	if _, err := svc.Approve(ctx, "dec-1", "  ", approvalKey); !errors.Is(err, app.ErrRebuildApprovalActorRequired) {
		t.Errorf("no actor: %v", err)
	}
	if _, err := svc.Approve(ctx, "nope", "pat", approvalKey); !errors.Is(err, app.ErrRebuildRecommendationNotFound) {
		t.Errorf("unknown id: %v", err)
	}
	// D10 item 6: with no build profile there is nothing to ask; it stays standing.
	rec := st.recs["dec-1"]
	rec.Decision.RecommendReason = domain.RebuildRecommendNoBuildProfile
	st.recs["dec-np"] = rec
	if ans, err := svc.Approve(ctx, "dec-np", "pat", approvalKey); err != nil || ans.Result != app.RebuildApprovalNoBuildProfile || ans.State != domain.RebuildRecStanding || len(st.writes) != 0 {
		t.Errorf("no profile = %+v (err %v)", ans, err)
	}
	st.writeErr = errors.New("db down")
	if _, err := svc.Approve(ctx, "dec-1", "pat", approvalKey); err == nil {
		t.Error("a write fault must be an error")
	}
	st.getErr = errors.New("db down")
	if _, err := svc.Approve(ctx, "dec-1", "pat", approvalKey); err == nil {
		t.Error("a read fault must be an error")
	}
	if _, err := svc.Latest(ctx, "rel-1"); err == nil {
		t.Error("a read fault must be an error")
	}
	// D46 item 7: tags that cannot be read refuse the approval; it fails closed.
	for name, tags := range map[string]app.ReleaseTagReader{"unread": releaseTags{err: errors.New("registry down")}, "not wired": nil} {
		closed, cst := approvalRig(t, domain.RebuildModeAsk, tags, app.RebuildApprovalApproved)
		if _, err := closed.Approve(ctx, "dec-1", "pat", approvalKey); !errors.Is(err, app.ErrRebuildModeUnread) || len(cst.writes) != 0 {
			t.Errorf("%s: err %v writes %d", name, err, len(cst.writes))
		}
	}
	// D46 item 3: a policy that keeps changing under the approval ends in "try again".
	busy, bst := approvalRig(t, domain.RebuildModeAsk, taggedRelease("rebuild:auto"), app.RebuildApprovalWritePolicyChanged)
	if _, err := busy.Approve(ctx, "dec-1", "pat", approvalKey); !errors.Is(err, app.ErrRebuildApprovalBusy) || len(bst.writes) != 3 {
		t.Errorf("busy: err %v writes %d", err, len(bst.writes))
	}
	once, ost := approvalRig(t, domain.RebuildModeAsk, taggedRelease("rebuild:auto"), app.RebuildApprovalWritePolicyChanged, app.RebuildApprovalApproved)
	if ans, err := once.Approve(ctx, "dec-1", "pat", approvalKey); err != nil || ans.Result != app.RebuildApprovalApproved || len(ost.writes) != 2 {
		t.Errorf("changed once: %+v err %v writes %d", ans, err, len(ost.writes))
	}
}

func TestRebuildApprovalReads(t *testing.T) {
	ctx := context.Background()
	svc, _ := approvalRig(t, domain.RebuildModeAsk, taggedRelease("rebuild:auto"))
	if rec, err := svc.Latest(ctx, " rel-1 "); err != nil || rec.Decision.ReleaseID != "rel-1" {
		t.Errorf("latest = %+v (err %v)", rec, err)
	}
	if _, err := svc.Latest(ctx, "rel-none"); !errors.Is(err, app.ErrRebuildRecommendationNotFound) {
		t.Errorf("no recommendation: %v", err)
	}
	if !svc.Now().Equal(triggerNow) {
		t.Error("the service clock")
	}
	var unwired *app.RebuildApprovalService
	if _, err := unwired.Latest(ctx, "rel-1"); !errors.Is(err, app.ErrRebuildApprovalUnavailable) {
		t.Errorf("unwired latest: %v", err)
	}
	if _, err := unwired.Recommendation(ctx, "dec-1"); !errors.Is(err, app.ErrRebuildApprovalUnavailable) {
		t.Errorf("unwired read: %v", err)
	}
	if _, err := unwired.Approve(ctx, "dec-1", "pat", approvalKey); !errors.Is(err, app.ErrRebuildApprovalUnavailable) {
		t.Errorf("unwired approve: %v", err)
	}
}

// D32: the sweep records each expiry once and does nothing else.
func TestRebuildExpirySweep(t *testing.T) {
	ctx := context.Background()
	rec := firstRecommendation(t)
	st := &approvalStore{recs: map[string]app.RebuildRecommendation{"dec-1": rec, "dec-2": rec}}
	sweep := app.NewRebuildExpirySweep(st, rebuildClock{triggerNow})
	if n, err := sweep.Tick(ctx); err != nil || n != 2 || len(st.expired) != 2 || !st.before.Equal(triggerNow.Add(-domain.RebuildRecommendationTTL)) {
		t.Fatalf("tick = %d (err %v) expired %v before %v", n, err, st.expired, st.before)
	}
	// Another writer made the move first: nothing is counted.
	st.notMoved = true
	if n, err := sweep.Tick(ctx); err != nil || n != 0 {
		t.Errorf("not moved = %d (err %v)", n, err)
	}
	st.expireErr = errors.New("db down")
	if _, err := sweep.Tick(ctx); err == nil {
		t.Error("an expiry fault must be an error")
	}
	st.listErr = errors.New("db down")
	if _, err := sweep.Tick(ctx); err == nil {
		t.Error("a list fault must be an error")
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	reported := make(chan struct{}, 8)
	go func() {
		sweep.RunEvery(cctx, time.Millisecond, func(int, error) {
			select {
			case reported <- struct{}{}:
			default:
			}
		})
		close(done)
	}()
	<-reported
	cancel()
	<-done
	rctx, rcancel := context.WithCancel(ctx)
	go func() { time.Sleep(5 * time.Millisecond); rcancel() }()
	sweep.RunEvery(rctx, time.Millisecond, nil)
}
