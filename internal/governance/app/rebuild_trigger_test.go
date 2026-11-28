package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type settled struct {
	trig     app.RebuildTrigger
	res      app.RebuildTriggerResult
	decision *domain.RebuildDecision
	note     app.OutboxNote
}

type triggerStore struct {
	pending   []app.RebuildTrigger
	listErr   error
	settleErr error
	settled   []settled
	records   []app.RebuildTriggerRecord
	limit     int
	// step R4: the recommendations the worker reads, and the expiries it records.
	status    app.RebuildRecommendationStatus
	statusErr error
	expired   []app.OutboxNote
	expireErr error
}

func (s *triggerStore) RebuildRecommendationStatus(context.Context, string) (app.RebuildRecommendationStatus, error) {
	return s.status, s.statusErr
}

func (s *triggerStore) ExpireRebuildRecommendation(_ context.Context, _ string, _ time.Time, note app.OutboxNote) (bool, error) {
	if s.expireErr != nil {
		return false, s.expireErr
	}
	s.expired = append(s.expired, note)
	return true, nil
}

func (s *triggerStore) PendingRebuildTriggers(context.Context, int) ([]app.RebuildTrigger, error) {
	return s.pending, s.listErr
}

func (s *triggerStore) SettleRebuildTrigger(_ context.Context, trig app.RebuildTrigger, res app.RebuildTriggerResult, d *domain.RebuildDecision, note app.OutboxNote) error {
	if s.settleErr != nil {
		return s.settleErr
	}
	s.settled = append(s.settled, settled{trig, res, d, note})
	return nil
}

func (s *triggerStore) RebuildTriggerRecords(_ context.Context, _ string, limit int) ([]app.RebuildTriggerRecord, error) {
	s.limit = limit
	return s.records, nil
}

type fixedIDs struct{}

func (fixedIDs) NewID() string { return "dec-1" }

type triggerLog struct{ msgs []string }

func (l *triggerLog) Error(msg, _ string, _ error) { l.msgs = append(l.msgs, msg) }

var triggerNow = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

// buildProfiles is the Registry build profile read, canned.
type buildProfiles struct {
	profile app.ReleaseBuildProfile
	err     error
	calls   int
	asked   string
}

func (b *buildProfiles) ReleaseBuildProfile(_ context.Context, releaseID string) (app.ReleaseBuildProfile, error) {
	b.calls++
	b.asked = releaseID
	return b.profile, b.err
}

const triggerProfileJSON = `{"image":"registry.example/app","args":{"BASE":"el8"}}`

func foundProfile() *buildProfiles {
	return &buildProfiles{profile: app.ReleaseBuildProfile{Found: true, Profile: []byte(triggerProfileJSON),
		Scope: "project", Revision: 3, SHA256: "abc123"}}
}

func triggerWorker(t *testing.T, st *triggerStore, mode domain.RebuildMode, tags []string, fixes app.ReleaseFixVerdictReader, log app.EvaluationLog) *app.RebuildTriggerWorker {
	t.Helper()
	return triggerWorkerWith(t, st, mode, tags, fixes, foundProfile(), log)
}

func triggerWorkerWith(t *testing.T, st *triggerStore, mode domain.RebuildMode, tags []string, fixes app.ReleaseFixVerdictReader, profiles app.BuildProfileReader, log app.EvaluationLog) *app.RebuildTriggerWorker {
	t.Helper()
	policy := app.NewRebuildPolicyService(&fakeRebuildPolicyStore{}, rebuildClock{}).WithTags(taggedRelease(tags...))
	if _, err := policy.PutInstallation(context.Background(), policyWith(mode, domain.SLABucketHigh), "alice"); err != nil {
		t.Fatal(err)
	}
	eval := app.NewRebuildEvaluationService(policy, rebuildFixture(), fixes, rebuildClock{triggerNow})
	return app.NewRebuildTriggerWorker(st, eval, profiles, fixedIDs{}, rebuildClock{triggerNow}, log)
}

func oneTrigger(age time.Duration) []app.RebuildTrigger {
	return []app.RebuildTrigger{{ID: 7, TriggerID: "evt-1", Source: "governance", Type: domain.RebuildTriggerFixAvailable,
		ReleaseID: "rel-1", ReceivedAt: triggerNow.Add(-age)}}
}

// D27, D29: a trigger that ends in recommend or request records ONE decision with the facts
// frozen, and its event carries that same decision. The mode picks the event.
func TestRebuildTriggerRecordsADecisionAndItsEvent(t *testing.T) {
	cases := []struct {
		mode      domain.RebuildMode
		outcome   string
		eventType string
		why       string
	}{
		{domain.RebuildModeAsk, domain.RebuildOutcomeRecommend, app.EventRebuildRecommended, domain.RebuildRecommendModeAsk},
		{domain.RebuildModeAuto, domain.RebuildOutcomeRequest, app.EventRebuildRequested, ""},
	}
	for _, c := range cases {
		st := &triggerStore{pending: oneTrigger(time.Minute)}
		w := triggerWorker(t, st, c.mode, []string{"rebuild:auto"}, rebuildFixVerdicts(), nil)
		if n := w.Tick(context.Background()); n != 1 || len(st.settled) != 1 {
			t.Fatalf("%s: settled %d %+v", c.mode, n, st.settled)
		}
		got := st.settled[0]
		d := got.decision
		if d == nil || got.trig.ID != 7 || got.res.Outcome != c.outcome || got.res.Reason != "" ||
			got.res.EffectiveMode != string(c.mode) || got.res.Considered != 5 || got.res.Targeted != 2 ||
			!got.res.SettledAt.Equal(triggerNow) {
			t.Fatalf("%s: result %+v decision %+v", c.mode, got.res, d)
		}
		if got.note.EventType != c.eventType || !got.note.OccurredAt.Equal(triggerNow) {
			t.Errorf("%s: note %+v", c.mode, got.note)
		}
		if ev, ok := got.note.Event.(domain.RebuildDecision); !ok || ev.DecisionID != d.DecisionID {
			t.Errorf("%s: the event must carry the decision, got %T", c.mode, got.note.Event)
		}
		if d.DecisionID != "dec-1" || d.ReleaseID != "rel-1" || d.ProductID != "prod-1" || d.ProjectID != "proj-1" ||
			d.TriggerID != "evt-1" || d.TriggerSource != "governance" || d.TriggerType != domain.RebuildTriggerFixAvailable ||
			d.Outcome != c.outcome || d.EffectiveMode != string(c.mode) || d.InstallationMode != string(c.mode) ||
			d.Tag != domain.RebuildTagAuto || d.TagLevel != domain.RebuildTagLevelRelease || !d.DecidedAt.Equal(triggerNow) {
			t.Errorf("%s: decision head %+v", c.mode, d)
		}
		// D10 item 7, D16: the profile is copied as stored and named by scope, revision, digest.
		if d.RecommendReason != c.why || string(d.Build) != triggerProfileJSON || d.BuildProfile == nil ||
			*d.BuildProfile != (domain.RebuildDecisionBuildProfile{Scope: "project", Revision: 3, SHA256: "abc123"}) {
			t.Errorf("%s: build %s %+v why %q", c.mode, d.Build, d.BuildProfile, d.RecommendReason)
		}
		p := d.Policy
		if p.ScopeKind != app.RebuildScopeInstallation || p.Version != 1 || !p.FixRequired || p.SeverityFloor != domain.SLABucketHigh ||
			p.Mode != string(c.mode) || p.CoolDownSeconds != int64(domain.RebuildCoolDownDefault/time.Second) {
			t.Errorf("%s: frozen policy %+v", c.mode, p)
		}
		if d.Considered != 5 || len(d.Targeted) != 2 || len(d.OtherStream) != 0 || d.OtherStream == nil ||
			d.Skipped[domain.RebuildSkippedDecided] != 1 {
			t.Fatalf("%s: decision body %+v", c.mode, d)
		}
		k, b := d.Targeted[0], d.Targeted[1]
		if k.FindingID != "f1" || k.CurrentVersion != "4.18.0-1.el8" || len(k.FixedVersions) != 1 ||
			k.FixSource != app.RebuildFixSourceVerdict || k.Score != 80 || k.ScoreSource != app.RebuildScoreSourceBase ||
			k.ClaimClass != "carrier" || k.Position != "none" || k.AssessmentState != app.RebuildAssessmentNotAssessed ||
			len(k.CountedBecause) != 1 {
			t.Errorf("%s: kernel entry %+v", c.mode, k)
		}
		if b.FindingID != "f2" || b.ClaimClass != "unknown" || !b.KnownExploited || b.ScoreSource != app.RebuildScoreSourceOwner {
			t.Errorf("%s: bash entry %+v", c.mode, b)
		}
	}
}

// D10 item 6, no profile, no request: with no build profile the decision is a recommendation
// that says so, whatever the mode, and carries no build.
func TestRebuildTriggerNoProfileNoRequest(t *testing.T) {
	for _, mode := range []domain.RebuildMode{domain.RebuildModeAuto, domain.RebuildModeAsk} {
		st := &triggerStore{pending: oneTrigger(time.Minute)}
		profiles := &buildProfiles{}
		w := triggerWorkerWith(t, st, mode, []string{"rebuild:auto"}, rebuildFixVerdicts(), profiles, nil)
		if n := w.Tick(context.Background()); n != 1 || len(st.settled) != 1 {
			t.Fatalf("%s: settled %d", mode, n)
		}
		got := st.settled[0]
		d := got.decision
		if d == nil || d.Outcome != domain.RebuildOutcomeRecommend || d.RecommendReason != domain.RebuildRecommendNoBuildProfile ||
			d.Build != nil || d.BuildProfile != nil || d.EffectiveMode != string(mode) {
			t.Fatalf("%s: decision %+v", mode, d)
		}
		if got.res.Outcome != domain.RebuildOutcomeRecommend || got.note.EventType != app.EventRebuildRecommended {
			t.Errorf("%s: result %+v note %q", mode, got.res, got.note.EventType)
		}
		if profiles.calls != 1 || profiles.asked != "rel-1" {
			t.Errorf("%s: profile read %d times for %q", mode, profiles.calls, profiles.asked)
		}
	}
}

// A build profile that cannot be read keeps the trigger open: it must not read as "no
// profile". A judgement that asks for nothing does not read the profile at all.
func TestRebuildTriggerProfileUnreadAndUnneeded(t *testing.T) {
	down := &buildProfiles{err: errors.New("registry down")}
	log := &triggerLog{}
	st := &triggerStore{pending: oneTrigger(time.Minute)}
	if n := triggerWorkerWith(t, st, domain.RebuildModeAuto, []string{"rebuild:auto"}, rebuildFixVerdicts(), down, log).Tick(context.Background()); n != 0 || len(st.settled) != 0 || len(log.msgs) != 1 {
		t.Fatalf("unread profile: settled %d %+v log %v", n, st.settled, log.msgs)
	}
	st = &triggerStore{pending: oneTrigger(time.Minute)}
	if n := triggerWorkerWith(t, st, domain.RebuildModeAuto, nil, rebuildFixVerdicts(), down, nil).Tick(context.Background()); n != 1 || down.calls != 1 {
		t.Fatalf("outcome none: settled %d, profile read %d times in all", n, down.calls)
	}
}

// A judgement that asks for nothing records the reason and no decision, and sends nothing.
func TestRebuildTriggerOutcomeNone(t *testing.T) {
	loose := func() fixVerdicts { return fixVerdicts{rows: []app.ReleaseFixVerdict{}} }
	cases := []struct {
		name   string
		tags   []string
		fixes  app.ReleaseFixVerdictReader
		reason string
		mode   string
	}{
		{"no tag", nil, rebuildFixVerdicts(), domain.RebuildNoneModeOff, string(domain.RebuildModeOff)},
		{"nothing counts", []string{"rebuild:ask"}, loose(), domain.RebuildNoneNothingCounts, string(domain.RebuildModeAsk)},
	}
	for _, c := range cases {
		st := &triggerStore{pending: oneTrigger(time.Minute)}
		w := triggerWorker(t, st, domain.RebuildModeAuto, c.tags, c.fixes, nil)
		if n := w.Tick(context.Background()); n != 1 || len(st.settled) != 1 {
			t.Fatalf("%s: settled %d", c.name, n)
		}
		got := st.settled[0]
		if got.decision != nil || got.note.EventType != "" || got.res.Outcome != domain.RebuildOutcomeNone ||
			got.res.Reason != c.reason || got.res.EffectiveMode != c.mode || got.res.Considered != 5 {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

// A Release that cannot be judged now keeps its trigger open: Knowledge unreadable must not be
// recorded as "nothing counts". After the wait limit the trigger is closed unjudged, and says so.
func TestRebuildTriggerWaitsThenGivesUp(t *testing.T) {
	unread := fixVerdicts{err: errors.New("knowledge down")}

	log := &triggerLog{}
	st := &triggerStore{pending: oneTrigger(time.Hour)}
	if n := triggerWorker(t, st, domain.RebuildModeAuto, []string{"rebuild:auto"}, unread, log).Tick(context.Background()); n != 0 || len(st.settled) != 0 || len(log.msgs) != 1 {
		t.Fatalf("young trigger: settled %d %+v log %v", n, st.settled, log.msgs)
	}
	// Silent without a log, and still open.
	st = &triggerStore{pending: oneTrigger(time.Hour)}
	if n := triggerWorker(t, st, domain.RebuildModeAuto, []string{"rebuild:auto"}, unread, nil).Tick(context.Background()); n != 0 {
		t.Fatalf("young trigger, no log: settled %d", n)
	}

	log = &triggerLog{}
	st = &triggerStore{pending: oneTrigger(domain.RebuildTriggerMaxAge)}
	if n := triggerWorker(t, st, domain.RebuildModeAuto, []string{"rebuild:auto"}, unread, log).Tick(context.Background()); n != 1 || len(st.settled) != 1 {
		t.Fatalf("old trigger: settled %d", n)
	}
	got := st.settled[0]
	if got.decision != nil || got.res.Outcome != domain.RebuildOutcomeNone || got.res.Reason != domain.RebuildNoneGaveUp ||
		got.res.EffectiveMode != "" || len(log.msgs) != 1 {
		t.Errorf("gave up: %+v log %v", got, log.msgs)
	}
}

// A store fault leaves the trigger open; a cancelled pass stops; one failure does not stop the
// pass for the others.
func TestRebuildTriggerFaults(t *testing.T) {
	ctx := context.Background()
	log := &triggerLog{}
	st := &triggerStore{listErr: errors.New("db down")}
	if n := triggerWorker(t, st, domain.RebuildModeAuto, nil, rebuildFixVerdicts(), log).Tick(ctx); n != 0 || len(log.msgs) != 1 {
		t.Errorf("list fault: %d %v", n, log.msgs)
	}
	two := append(oneTrigger(time.Minute), oneTrigger(time.Minute)...)
	two[1].ID = 8
	st = &triggerStore{pending: two, settleErr: errors.New("db down")}
	log = &triggerLog{}
	w := triggerWorker(t, st, domain.RebuildModeAuto, []string{"rebuild:auto"}, rebuildFixVerdicts(), log)
	if n := w.Tick(ctx); n != 0 || len(log.msgs) != 2 {
		t.Errorf("settle fault: %d %v", n, log.msgs)
	}
	// The same failure on the next pass is not said again; once it clears, both close.
	if n := w.Tick(ctx); n != 0 || len(log.msgs) != 2 {
		t.Errorf("second pass: %d %v, want no new report", n, log.msgs)
	}
	st.settleErr = nil
	if n := w.Tick(ctx); n != 2 || len(log.msgs) != 2 {
		t.Errorf("after recovery: %d %v", n, log.msgs)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	st = &triggerStore{pending: oneTrigger(time.Minute)}
	if n := triggerWorker(t, st, domain.RebuildModeAuto, nil, rebuildFixVerdicts(), nil).Tick(cancelled); n != 0 || len(st.settled) != 0 {
		t.Errorf("cancelled: %d", n)
	}
}

func TestRebuildTriggerRunEveryStopsWithTheContext(t *testing.T) {
	st := &triggerStore{pending: oneTrigger(time.Minute)}
	w := triggerWorker(t, st, domain.RebuildModeAuto, nil, rebuildFixVerdicts(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.RunEvery(ctx, time.Millisecond); close(done) }()
	time.Sleep(20 * time.Millisecond) // long enough for a pass or two
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunEvery did not stop")
	}
}

func TestRebuildDecisionReaderClampsTheLimit(t *testing.T) {
	ctx := context.Background()
	var none *app.RebuildDecisionReader
	if _, err := none.ForRelease(ctx, "rel-1", 0); !errors.Is(err, app.ErrRebuildDecisionsUnavailable) {
		t.Errorf("nil reader: %v", err)
	}
	if _, err := app.NewRebuildDecisionReader(nil).ForRelease(ctx, "rel-1", 0); !errors.Is(err, app.ErrRebuildDecisionsUnavailable) {
		t.Errorf("nil store: %v", err)
	}
	st := &triggerStore{records: []app.RebuildTriggerRecord{{Settled: true}}}
	r := app.NewRebuildDecisionReader(st)
	for in, want := range map[int]int{0: app.RebuildDecisionsDefaultLimit, -3: app.RebuildDecisionsDefaultLimit, 5: 5, 9999: app.RebuildDecisionsMaxLimit} {
		got, err := r.ForRelease(ctx, "rel-1", in)
		if err != nil || len(got) != 1 || st.limit != want {
			t.Errorf("limit %d -> %d (want %d) err %v", in, st.limit, want, err)
		}
	}
}

type cycleTriggers struct {
	got       [][4]string
	closed    [][]string
	retrigger bool
	err       error
	markErr   error
}

func (c *cycleTriggers) RecordRebuildTrigger(_ context.Context, id, source, typ, release string) error {
	c.got = append(c.got, [4]string{id, source, typ, release})
	return c.err
}

func (c *cycleTriggers) MarkRebuildCyclesClosed(_ context.Context, ids []string) (bool, error) {
	c.closed = append(c.closed, ids)
	return c.retrigger, c.markErr
}

// EDR-REBUILD-01 D21, D44 item 7: a closed rebuild cycle ends the hold of the approved
// recommendations it carried. It becomes a trigger, under the id of the event, only when
// something waited for it: a decision that joined, or a trigger that was kept back.
func TestOnRebuildCycleClosed(t *testing.T) {
	ctx := context.Background()
	rec := &cycleTriggers{}
	coord := app.NewCoordinator(writeSvc(newRepo())).WithRebuildTriggers(rec)
	in := app.InboundRebuildCycleClosed{EventID: "ev-1", ReleaseID: "rel-1", DecisionID: "dec-1", Joined: []string{"dec-2", " "}}
	if err := coord.OnRebuildCycleClosed(ctx, in); err != nil {
		t.Fatal(err)
	}
	want := [4]string{"ev-1", "communication", domain.RebuildTriggerCycleClosed, "rel-1"}
	if len(rec.got) != 1 || rec.got[0] != want || len(rec.closed) != 1 || len(rec.closed[0]) != 2 || rec.closed[0][0] != "dec-1" || rec.closed[0][1] != "dec-2" {
		t.Fatalf("recorded = %v closed = %v", rec.got, rec.closed)
	}
	// Nobody joined and nothing was kept back: the hold ends, and no trigger is recorded.
	alone := app.InboundRebuildCycleClosed{EventID: "ev-2", ReleaseID: "rel-1", DecisionID: "dec-1"}
	if err := coord.OnRebuildCycleClosed(ctx, alone); err != nil || len(rec.got) != 1 || len(rec.closed) != 2 {
		t.Fatalf("alone: err %v recorded %v closed %v", err, rec.got, rec.closed)
	}
	// A trigger was kept back by the approved recommendation: the closure is a trigger.
	rec.retrigger = true
	if err := coord.OnRebuildCycleClosed(ctx, alone); err != nil || len(rec.got) != 2 {
		t.Fatalf("kept back: err %v recorded %v", err, rec.got)
	}
	for _, in := range []app.InboundRebuildCycleClosed{{EventID: "ev-2"}, {ReleaseID: "rel-1"}, {EventID: " ", ReleaseID: "rel-1"}} {
		if err := coord.OnRebuildCycleClosed(ctx, in); err != nil || len(rec.got) != 2 {
			t.Errorf("%+v: err=%v recorded=%d, want nothing recorded", in, err, len(rec.got))
		}
	}
	rec.err = errors.New("db down")
	if err := coord.OnRebuildCycleClosed(ctx, in); err == nil {
		t.Error("a store fault must surface so the event is retried")
	}
	rec.markErr = errors.New("db down")
	if err := coord.OnRebuildCycleClosed(ctx, alone); err == nil {
		t.Error("a fault while ending the hold must surface")
	}
	if err := app.NewCoordinator(writeSvc(newRepo())).OnRebuildCycleClosed(ctx, in); err != nil {
		t.Errorf("no recorder: %v", err)
	}
}
