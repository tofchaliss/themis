//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// publishEvaluation runs one release evaluation through the queue, as the worker does.
func publishEvaluation(t *testing.T, st *store.Store, release, sbom, cause string) {
	t.Helper()
	ctx := context.Background()
	if err := st.EnqueuePendingReleaseEvaluation(ctx, release, sbom, cause); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListPendingReleaseEvaluations(ctx, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("pending = %+v %v", rows, err)
	}
	ev := domain.NewReleaseEvaluated("prod-1", "prj-1", release, sbom, cause, domain.SeverityCounts{})
	if err := st.PublishEvaluatedAndMark(ctx, rows[0], ev, epoch); err != nil {
		t.Fatal(err)
	}
}

// EDR-REBUILD-01 D3, D27: a trigger is written with its event and carries that event's id. A
// new SBOM's evaluation and a fix-available announcement are triggers; a re-discovery is not.
func TestRebuildTriggersAreWrittenWithTheirEvents(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	publishEvaluation(t, st, "rel-1", "sb-1", domain.CauseNewSBOM)
	publishEvaluation(t, st, "rel-1", "sb-1", domain.CauseRediscovery)
	at := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	notices := []app.FixNotice{{ReleaseID: "rel-2", FaultlineID: "fl-1", CVE: "CVE-2026-1", PURL: "pkg:rpm/redhat/kernel@1",
		Package: "kernel", Ecosystem: "rpm", Fix: "0:2.el8", LearnedAt: at}}
	if err := st.RecordFixNotices(ctx, notices); err != nil {
		t.Fatal(err)
	}
	ev := domain.NewFixAvailable("rel-2", nil, at)
	if err := st.MarkFixNoticesAnnounced(ctx, "rel-2", notices, app.OutboxNote{EventType: app.EventFixAvailable, Event: ev, OccurredAt: at}); err != nil {
		t.Fatal(err)
	}

	pending, err := st.PendingRebuildTriggers(ctx, 10)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending = %+v %v, want the new SBOM and the fix (not the re-discovery)", pending, err)
	}
	sbom, fix := pending[0], pending[1]
	if sbom.Type != domain.RebuildTriggerNewSBOM || sbom.ReleaseID != "rel-1" || sbom.Source != "governance" || sbom.ReceivedAt.IsZero() ||
		fix.Type != domain.RebuildTriggerFixAvailable || fix.ReleaseID != "rel-2" {
		t.Fatalf("triggers = %+v", pending)
	}
	// The trigger id is the id of the event that caused it.
	for _, trig := range pending {
		if n := count(t, pool, "SELECT count(*) FROM governance_outbox WHERE id = '"+trig.TriggerID+"'"); n != 1 {
			t.Errorf("trigger %s names no outbox event", trig.TriggerID)
		}
	}
	if one, err := st.PendingRebuildTriggers(ctx, 1); err != nil || len(one) != 1 || one[0].ID != sbom.ID {
		t.Errorf("limit 1 = %+v %v, want the oldest", one, err)
	}
}

// D27, D29: closing a trigger with a decision stores the decision and its event in the same
// transaction, once. Closing with outcome none stores only the reason.
func TestSettleRebuildTrigger(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	publishEvaluation(t, st, "rel-1", "sb-1", domain.CauseNewSBOM)
	publishEvaluation(t, st, "rel-1", "sb-2", domain.CauseNewSBOM)
	pending, err := st.PendingRebuildTriggers(ctx, 10)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending = %+v %v", pending, err)
	}
	if recs, err := st.RebuildTriggerRecords(ctx, "rel-1", 10); err != nil || len(recs) != 2 || recs[0].Settled || recs[0].Decision != nil {
		t.Fatalf("open records = %+v %v", recs, err)
	}
	at := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

	// The first ends in none.
	none := app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeNone, Reason: domain.RebuildNoneModeOff,
		EffectiveMode: "off", ModeSetBy: "tag", Considered: 9, SettledAt: at}
	if err := st.SettleRebuildTrigger(ctx, pending[0], none, nil, app.OutboxNote{}); err != nil {
		t.Fatal(err)
	}

	// The second ends in a recommendation.
	entry := domain.RebuildDecisionEntry{FindingID: "f1", CVE: "CVE-2026-1", PURL: "pkg:rpm/redhat/kernel@1", CurrentVersion: "1",
		FixedVersions: []string{"0:2.el8"}, FixSource: app.RebuildFixSourceVerdict, Severity: domain.SLABucketHigh, Score: 80,
		ScoreSource: app.RebuildScoreSourceBase, ClaimClass: "carrier", Position: "none",
		AssessmentState: app.RebuildAssessmentNotAssessed, CountedBecause: []string{domain.RebuildCountedSeverityFloor}}
	decision := domain.RebuildDecision{
		DecisionID: "dec-1", ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "prj-1",
		TriggerID: pending[1].TriggerID, TriggerSource: pending[1].Source, TriggerType: pending[1].Type,
		Outcome: domain.RebuildOutcomeRecommend, EffectiveMode: "ask", EffectiveModeSetBy: "installation", InstallationMode: "ask",
		Tag: domain.RebuildTagAsk, TagLevel: domain.RebuildTagLevelRelease,
		Policy:     domain.RebuildDecisionPolicy{ScopeKind: "installation", Version: 2, FixRequired: true, SeverityFloor: domain.SLABucketHigh, Mode: "ask", CoolDownSeconds: 86400},
		Considered: 9, Skipped: map[string]int{domain.RebuildSkippedBelowFloor: 8},
		Targeted: []domain.RebuildDecisionEntry{entry}, OtherStream: []domain.RebuildDecisionEntry{}, DecidedAt: at,
		RecommendReason: domain.RebuildRecommendModeAsk,
		Build:           []byte(`{"image":"registry.example/app","args":{"BASE":"el8"}}`),
		BuildProfile:    &domain.RebuildDecisionBuildProfile{Scope: "project", Revision: 3, SHA256: "abc123"},
	}
	rec := app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeRecommend, EffectiveMode: "ask", ModeSetBy: "installation",
		Considered: 9, Targeted: 1, SettledAt: at}
	note := app.OutboxNote{EventType: app.EventRebuildRecommended, Event: decision, OccurredAt: at}
	if err := st.SettleRebuildTrigger(ctx, pending[1], rec, &decision, note); err != nil {
		t.Fatal(err)
	}
	// A second pass over the same trigger writes nothing.
	if err := st.SettleRebuildTrigger(ctx, pending[1], rec, &decision, note); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, "SELECT count(*) FROM rebuild_decisions"); n != 1 {
		t.Errorf("decisions = %d, want 1", n)
	}
	var subject, schemaRef string
	var payload []byte
	if err := pool.QueryRow(ctx, "SELECT subject, schema_ref, payload FROM governance_outbox WHERE event_type=$1", app.EventRebuildRecommended).
		Scan(&subject, &schemaRef, &payload); err != nil {
		t.Fatalf("exactly one rebuild event expected: %v", err)
	}
	if subject != "rel-1" || schemaRef != "governance.rebuild_recommended.v1" {
		t.Errorf("outbox note = %s / %s", subject, schemaRef)
	}
	if left, err := st.PendingRebuildTriggers(ctx, 10); err != nil || len(left) != 0 {
		t.Errorf("still pending = %+v %v", left, err)
	}

	recs, err := st.RebuildTriggerRecords(ctx, "rel-1", 10)
	if err != nil || len(recs) != 2 {
		t.Fatalf("records = %+v %v", recs, err)
	}
	var withDecision, withReason app.RebuildTriggerRecord
	for _, r := range recs {
		if r.Decision != nil {
			withDecision = r
		} else {
			withReason = r
		}
	}
	got := withDecision.Decision
	if got == nil || !withDecision.Settled || withDecision.Result.Outcome != domain.RebuildOutcomeRecommend ||
		withDecision.Result.Targeted != 1 || !withDecision.Result.SettledAt.Equal(at) {
		t.Fatalf("decided record = %+v", withDecision)
	}
	if got.DecisionID != "dec-1" || got.Policy.Version != 2 || got.Policy.CoolDownSeconds != 86400 || len(got.Targeted) != 1 ||
		got.Targeted[0].FixedVersions[0] != "0:2.el8" || got.Skipped[domain.RebuildSkippedBelowFloor] != 8 || !got.DecidedAt.Equal(at) ||
		got.TriggerID != pending[1].TriggerID {
		t.Errorf("frozen facts read back = %+v", got)
	}
	// The build profile is frozen with the decision: the same JSON value, named by revision.
	var build struct {
		Image string            `json:"image"`
		Args  map[string]string `json:"args"`
	}
	if err := json.Unmarshal(got.Build, &build); err != nil || build.Image != "registry.example/app" || build.Args["BASE"] != "el8" ||
		got.RecommendReason != domain.RebuildRecommendModeAsk || got.BuildProfile == nil ||
		*got.BuildProfile != (domain.RebuildDecisionBuildProfile{Scope: "project", Revision: 3, SHA256: "abc123"}) {
		t.Errorf("frozen build read back = %s %+v %q (%v)", got.Build, got.BuildProfile, got.RecommendReason, err)
	}
	if !withReason.Settled || withReason.Result.Outcome != domain.RebuildOutcomeNone || withReason.Result.Reason != domain.RebuildNoneModeOff ||
		withReason.Result.EffectiveMode != "off" || withReason.Result.ModeSetBy != "tag" || withReason.Result.Considered != 9 {
		t.Errorf("none record = %+v", withReason)
	}
	if other, err := st.RebuildTriggerRecords(ctx, "rel-other", 10); err != nil || other == nil || len(other) != 0 {
		t.Errorf("another release = %+v %v, want an empty list", other, err)
	}
	if one, err := st.RebuildTriggerRecords(ctx, "rel-1", 1); err != nil || len(one) != 1 {
		t.Errorf("limit 1 = %d %v", len(one), err)
	}
}

// EDR-REBUILD-01 D21: a closed rebuild cycle is stored as an open trigger of the third kind
// (migration 31 lets the type in), once per event id, and the worker reads it like the others.
func TestRecordRebuildTriggerFromAClosedCycle(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := st.RecordRebuildTrigger(ctx, "ev-1", "communication", domain.RebuildTriggerCycleClosed, "rel-1"); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := st.PendingRebuildTriggers(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %+v %v, want one trigger for one event", pending, err)
	}
	if p := pending[0]; p.TriggerID != "ev-1" || p.Source != "communication" || p.Type != domain.RebuildTriggerCycleClosed || p.ReleaseID != "rel-1" {
		t.Errorf("trigger = %+v", p)
	}
	if err := st.RecordRebuildTrigger(ctx, "ev-2", "communication", "made_up", "rel-1"); err == nil {
		t.Error("a trigger type outside the closed set must be refused by the table")
	}
}

// recommendationFor is a recommendation with one targeted component, decided at at.
func recommendationFor(id, release string, trig app.RebuildTrigger, at time.Time) domain.RebuildDecision {
	return domain.RebuildDecision{
		DecisionID: id, ReleaseID: release, ProductID: "prod-1", ProjectID: "prj-1",
		TriggerID: trig.TriggerID, TriggerSource: trig.Source, TriggerType: trig.Type,
		Outcome: domain.RebuildOutcomeRecommend, RecommendReason: domain.RebuildRecommendModeAsk,
		EffectiveMode: "ask", EffectiveModeSetBy: "installation", InstallationMode: "ask",
		Policy:      domain.RebuildDecisionPolicy{ScopeKind: "installation", Version: 1, Mode: "ask"},
		Skipped:     map[string]int{},
		Targeted:    []domain.RebuildDecisionEntry{{FindingID: "f1", CVE: "CVE-2026-1", PURL: "pkg:rpm/redhat/kernel@1", FixedVersions: []string{}, CountedBecause: []string{}}},
		OtherStream: []domain.RebuildDecisionEntry{}, DecidedAt: at,
		Build:        []byte(`{"job":"team/build-image"}`),
		BuildProfile: &domain.RebuildDecisionBuildProfile{Scope: "project", Revision: 1, SHA256: "ab"},
	}
}

func recommend(d domain.RebuildDecision) (app.RebuildTriggerResult, app.OutboxNote) {
	return app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeRecommend, EffectiveMode: "ask", ModeSetBy: "installation", Targeted: 1, SettledAt: d.DecidedAt},
		app.OutboxNote{EventType: app.EventRebuildRecommended, Event: d, OccurredAt: d.DecidedAt}
}

// nextTrigger records one more trigger for the Release and returns it.
func nextTrigger(t *testing.T, st *store.Store, id, release string) app.RebuildTrigger {
	t.Helper()
	ctx := context.Background()
	if err := st.RecordRebuildTrigger(ctx, id, "communication", domain.RebuildTriggerCycleClosed, release); err != nil {
		t.Fatal(err)
	}
	pending, err := st.PendingRebuildTriggers(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pending {
		if p.TriggerID == id {
			return p
		}
	}
	t.Fatalf("trigger %s not pending", id)
	return app.RebuildTrigger{}
}

// EDR-REBUILD-01 D41, D44: a Release has one standing recommendation. A different ask supersedes
// it in the same transaction, an equal one points to it, and a write that rested on a
// recommendation that moved first writes nothing.
func TestStandingRebuildRecommendation(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	at := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

	first := recommendationFor("dec-1", "rel-1", nextTrigger(t, st, "ev-1", "rel-1"), at)
	res, note := recommend(first)
	if err := st.SettleRebuildTrigger(ctx, nextTrigger(t, st, "ev-1", "rel-1"), res, &first, note); err != nil {
		t.Fatal(err)
	}
	status, err := st.RebuildRecommendationStatus(ctx, "rel-1")
	if err != nil || status.Standing == nil || status.Standing.Decision.DecisionID != "dec-1" || status.Standing.State != domain.RebuildRecStanding ||
		status.ApprovedOpen != nil || !status.Standing.StateAt.Equal(at) {
		t.Fatalf("status = %+v %v", status, err)
	}

	// A second recommendation that does not end the first meets the one-standing rule.
	second := recommendationFor("dec-2", "rel-1", nextTrigger(t, st, "ev-2", "rel-1"), at.Add(time.Hour))
	second.Supersedes = "dec-1"
	res, note = recommend(second)
	if err := st.SettleRebuildTrigger(ctx, nextTrigger(t, st, "ev-2", "rel-1"), res, &second, note); !errors.Is(err, app.ErrRebuildStandingChanged) {
		t.Fatalf("a second standing recommendation: %v", err)
	}
	if n := count(t, pool, "SELECT count(*) FROM rebuild_triggers WHERE trigger_id = 'ev-2' AND settled_at IS NULL"); n != 1 {
		t.Fatal("the refused write must leave its trigger open")
	}
	// An equal ask points to the standing one and records nothing else.
	same := app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeUnchanged, PointsTo: "dec-1", EffectiveMode: "ask", SettledAt: at.Add(time.Hour)}
	if err := st.SettleRebuildTrigger(ctx, nextTrigger(t, st, "ev-3", "rel-1"), same, nil, app.OutboxNote{}); err != nil {
		t.Fatal(err)
	}
	recs, err := st.RebuildTriggerRecords(ctx, "rel-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	var unchanged *app.RebuildTriggerRecord
	for i := range recs {
		if recs[i].TriggerID == "ev-3" {
			unchanged = &recs[i]
		}
	}
	if unchanged == nil || unchanged.Result.Outcome != domain.RebuildOutcomeUnchanged || unchanged.Decision == nil || unchanged.Decision.DecisionID != "dec-1" {
		t.Fatalf("unchanged trigger = %+v", unchanged)
	}
	// Superseding it: the old one ends and names the new one, in one transaction.
	res.EndStanding, res.EndState = "dec-1", domain.RebuildRecSuperseded
	if err := st.SettleRebuildTrigger(ctx, nextTrigger(t, st, "ev-2", "rel-1"), res, &second, note); err != nil {
		t.Fatal(err)
	}
	old, found, err := st.RebuildRecommendation(ctx, "dec-1")
	if err != nil || !found || old.State != domain.RebuildRecSuperseded || old.SupersededBy != "dec-2" {
		t.Fatalf("superseded = %+v %v", old, err)
	}
	latest, found, err := st.LatestRebuildRecommendation(ctx, "rel-1")
	if err != nil || !found || latest.Decision.DecisionID != "dec-2" || latest.Decision.Supersedes != "dec-1" || latest.State != domain.RebuildRecStanding {
		t.Fatalf("latest = %+v %v", latest, err)
	}
	// Each guard misses once the recommendation it rested on has moved.
	for name, stale := range map[string]app.RebuildTriggerResult{
		"unchanged against a superseded one": {Outcome: domain.RebuildOutcomeUnchanged, PointsTo: "dec-1", SettledAt: at},
		"ending one that already ended":      {Outcome: domain.RebuildOutcomeNone, EndStanding: "dec-1", EndState: domain.RebuildRecWithdrawn, SettledAt: at},
		"kept back by one not approved":      {Outcome: domain.RebuildOutcomeNone, Reason: domain.RebuildNoneCycleOpen, Retrigger: "dec-2", SettledAt: at},
	} {
		if err := st.SettleRebuildTrigger(ctx, nextTrigger(t, st, "ev-stale-"+name, "rel-1"), stale, nil, app.OutboxNote{}); !errors.Is(err, app.ErrRebuildStandingChanged) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Nothing to ask for any more: the standing one is withdrawn and names no successor.
	gone := app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeNone, Reason: domain.RebuildNoneNothingCounts, EndStanding: "dec-2", EndState: domain.RebuildRecWithdrawn, SettledAt: at.Add(2 * time.Hour)}
	if err := st.SettleRebuildTrigger(ctx, nextTrigger(t, st, "ev-4", "rel-1"), gone, nil, app.OutboxNote{}); err != nil {
		t.Fatal(err)
	}
	if w, _, _ := st.RebuildRecommendation(ctx, "dec-2"); w.State != domain.RebuildRecWithdrawn || w.SupersededBy != "" {
		t.Errorf("withdrawn = %+v", w)
	}
	if status, _ := st.RebuildRecommendationStatus(ctx, "rel-1"); status.Standing != nil {
		t.Errorf("nothing must be standing: %+v", status.Standing)
	}
	if _, found, err := st.RebuildRecommendation(ctx, "nope"); err != nil || found {
		t.Errorf("unknown id: %v %v", found, err)
	}
	if _, found, err := st.LatestRebuildRecommendation(ctx, "rel-none"); err != nil || found {
		t.Errorf("no recommendation: %v %v", found, err)
	}
}

func standingRecommendation(t *testing.T, st *store.Store, id, release string, at time.Time) domain.RebuildDecision {
	t.Helper()
	trig := nextTrigger(t, st, "ev-"+id, release)
	d := recommendationFor(id, release, trig, at)
	res, note := recommend(d)
	if err := st.SettleRebuildTrigger(context.Background(), trig, res, &d, note); err != nil {
		t.Fatal(err)
	}
	return d
}

func approvalWrite(d domain.RebuildDecision, now time.Time, approve bool, expected domain.RebuildPolicyVersions) app.RebuildApprovalWrite {
	a := domain.RebuildApproval{Actor: "pat", KeyName: "deciders", KeyScopes: []string{"product:prod-1"}, ApprovedAt: now,
		PolicyVersions: expected, Tag: "auto", TagLevel: "release", TagsReadAt: now}
	return app.RebuildApprovalWrite{Decision: d, Now: now, Expected: expected, Approve: approve, Approval: a, TriggerID: "trig-" + d.DecisionID,
		Request: app.OutboxNote{EventType: app.EventRebuildRequested, Event: domain.ApprovedRebuildRequest(d, a), OccurredAt: now},
		Expired: app.OutboxNote{EventType: app.EventRebuildRecommendationExpired, Event: domain.NewRebuildRecommendationExpired(d, now), OccurredAt: now}}
}

// D15, D45, D46: the approval is one conditional write. It checks the policy versions under the
// gate, expires first, then approves with the request or withdraws with a trigger.
func TestApproveRebuildRecommendation(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	at := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	now := at.Add(time.Hour)
	none := domain.RebuildPolicyVersions{}

	// A policy version that is not what the caller saw: nothing is written.
	d := standingRecommendation(t, st, "dec-1", "rel-1", at)
	if got, err := st.ApproveRebuildRecommendation(ctx, approvalWrite(d, now, true, domain.RebuildPolicyVersions{Installation: 4})); err != nil || got != app.RebuildApprovalWritePolicyChanged {
		t.Fatalf("stale versions = %q %v", got, err)
	}
	// With the versions as stored (an installation policy, and one for the Product) it approves.
	inst, err := st.PutRebuildPolicy(ctx, app.RebuildPolicyRecord{ScopeKind: app.RebuildScopeInstallation, Policy: domain.DefaultRebuildPolicy(), UpdatedAt: at, UpdatedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	prod, err := st.PutRebuildPolicy(ctx, app.RebuildPolicyRecord{ScopeKind: app.RebuildScopeProduct, ScopeID: "prod-1", Policy: domain.DefaultRebuildPolicy(), UpdatedAt: at, UpdatedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	seen := domain.RebuildPolicyVersions{Installation: inst.Version, Product: prod.Version}
	if got, err := st.ApproveRebuildRecommendation(ctx, approvalWrite(d, now, true, none)); err != nil || got != app.RebuildApprovalWritePolicyChanged {
		t.Fatalf("policies appeared = %q %v", got, err)
	}
	if got, err := st.ApproveRebuildRecommendation(ctx, approvalWrite(d, now, true, seen)); err != nil || got != app.RebuildApprovalApproved {
		t.Fatalf("approve = %q %v", got, err)
	}
	rec, _, err := st.RebuildRecommendation(ctx, "dec-1")
	if err != nil || rec.State != domain.RebuildRecApproved || rec.Approval == nil || rec.Approval.Actor != "pat" ||
		rec.Approval.PolicyVersions != seen || rec.CycleClosed || !rec.StateAt.Equal(now) || rec.Decision.Outcome != domain.RebuildOutcomeRecommend {
		t.Fatalf("approved = %+v %v", rec, err)
	}
	var payload []byte
	if err := pool.QueryRow(ctx, "SELECT payload FROM governance_outbox WHERE event_type = $1", app.EventRebuildRequested).Scan(&payload); err != nil {
		t.Fatalf("exactly one request expected: %v", err)
	}
	var req domain.RebuildDecision
	if err := json.Unmarshal(payload, &req); err != nil || req.DecisionID != "dec-1" || req.Outcome != domain.RebuildOutcomeRequest || req.Approval == nil || req.Approval.Actor != "pat" {
		t.Fatalf("request = %+v %v", req, err)
	}
	// A second approval of the same one finds it no longer standing, and publishes nothing.
	if got, err := st.ApproveRebuildRecommendation(ctx, approvalWrite(d, now, true, seen)); err != nil || got != app.RebuildApprovalNotStanding {
		t.Fatalf("second approval = %q %v", got, err)
	}
	if n := count(t, pool, "SELECT count(*) FROM governance_outbox WHERE event_type = '"+app.EventRebuildRequested+"'"); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
	// It holds new recommendations back until its cycle closes; a trigger kept back is noted.
	status, err := st.RebuildRecommendationStatus(ctx, "rel-1")
	if err != nil || status.Standing != nil || status.ApprovedOpen == nil || status.ApprovedOpen.Decision.DecisionID != "dec-1" {
		t.Fatalf("status = %+v %v", status, err)
	}
	kept := app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeNone, Reason: domain.RebuildNoneCycleOpen, Retrigger: "dec-1", SettledAt: now}
	if err := st.SettleRebuildTrigger(ctx, nextTrigger(t, st, "ev-kept", "rel-1"), kept, nil, app.OutboxNote{}); err != nil {
		t.Fatal(err)
	}
	if retrigger, err := st.MarkRebuildCyclesClosed(ctx, []string{"dec-1", "dec-unknown"}); err != nil || !retrigger {
		t.Fatalf("closing = %v %v, want the kept-back trigger reported", retrigger, err)
	}
	if retrigger, err := st.MarkRebuildCyclesClosed(ctx, []string{"dec-1"}); err != nil || retrigger {
		t.Errorf("closing twice = %v %v", retrigger, err)
	}
	if retrigger, err := st.MarkRebuildCyclesClosed(ctx, nil); err != nil || retrigger {
		t.Errorf("closing nothing = %v %v", retrigger, err)
	}
	if status, _ := st.RebuildRecommendationStatus(ctx, "rel-1"); status.ApprovedOpen != nil {
		t.Errorf("the hold must end with the closure: %+v", status.ApprovedOpen)
	}
	if rec, _, _ := st.RebuildRecommendation(ctx, "dec-1"); !rec.CycleClosed {
		t.Error("the closure must show on the recommendation")
	}

	// Mode no longer ask: withdrawn, with a trigger of its own kind, and no request.
	d2 := standingRecommendation(t, st, "dec-2", "rel-2", at)
	if got, err := st.ApproveRebuildRecommendation(ctx, approvalWrite(d2, now, false, domain.RebuildPolicyVersions{Installation: inst.Version, Product: prod.Version})); err != nil || got != app.RebuildApprovalWithdrawn {
		t.Fatalf("withdraw = %q %v", got, err)
	}
	if rec, _, _ := st.RebuildRecommendation(ctx, "dec-2"); rec.State != domain.RebuildRecWithdrawn || rec.Approval != nil {
		t.Errorf("withdrawn = %+v", rec)
	}
	if n := count(t, pool, "SELECT count(*) FROM rebuild_triggers WHERE trigger_type = 'mode_changed' AND trigger_id = 'trig-dec-2' AND release_id = 'rel-2' AND settled_at IS NULL"); n != 1 {
		t.Errorf("mode_changed triggers = %d, want 1", n)
	}

	// Past its 7 days: expired first, whatever was asked, with the event and no request.
	d3 := standingRecommendation(t, st, "dec-3", "rel-3", at)
	late := at.Add(domain.RebuildRecommendationTTL)
	if got, err := st.ApproveRebuildRecommendation(ctx, approvalWrite(d3, late, true, seen)); err != nil || got != app.RebuildApprovalExpired {
		t.Fatalf("expired = %q %v", got, err)
	}
	if rec, _, _ := st.RebuildRecommendation(ctx, "dec-3"); rec.State != domain.RebuildRecExpired {
		t.Errorf("expired = %+v", rec)
	}
	if n := count(t, pool, "SELECT count(*) FROM governance_outbox WHERE event_type = '"+app.EventRebuildRecommendationExpired+"' AND subject = 'rel-3'"); n != 1 {
		t.Errorf("expiry events = %d, want 1", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM governance_outbox WHERE event_type = '"+app.EventRebuildRequested+"'"); n != 1 {
		t.Errorf("requests = %d, want still 1", n)
	}
}

// D26, D32, D46 item 1: the expiry is one conditional move with one event.
func TestExpireRebuildRecommendation(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	old := standingRecommendation(t, st, "dec-1", "rel-1", at)
	standingRecommendation(t, st, "dec-2", "rel-2", at.Add(10*24*time.Hour))
	now := at.Add(domain.RebuildRecommendationTTL)

	due, err := st.StandingRebuildRecommendationsBefore(ctx, now.Add(-domain.RebuildRecommendationTTL), 10)
	if err != nil || len(due) != 1 || due[0].Decision.DecisionID != "dec-1" {
		t.Fatalf("due = %+v %v", due, err)
	}
	note := app.OutboxNote{EventType: app.EventRebuildRecommendationExpired, Event: domain.NewRebuildRecommendationExpired(old, now), OccurredAt: now}
	if moved, err := st.ExpireRebuildRecommendation(ctx, "dec-1", now, note); err != nil || !moved {
		t.Fatalf("expire = %v %v", moved, err)
	}
	if moved, err := st.ExpireRebuildRecommendation(ctx, "dec-1", now, note); err != nil || moved {
		t.Errorf("expire twice = %v %v", moved, err)
	}
	if moved, err := st.ExpireRebuildRecommendation(ctx, "nope", now, note); err != nil || moved {
		t.Errorf("unknown id = %v %v", moved, err)
	}
	var schemaRef string
	if err := pool.QueryRow(ctx, "SELECT schema_ref FROM governance_outbox WHERE event_type = $1", app.EventRebuildRecommendationExpired).Scan(&schemaRef); err != nil ||
		schemaRef != "governance.rebuild_recommendation_expired.v1" {
		t.Fatalf("exactly one expiry event expected: %q %v", schemaRef, err)
	}
	if due, _ := st.StandingRebuildRecommendationsBefore(ctx, now, 10); len(due) != 0 {
		t.Errorf("still due = %+v", due)
	}
}
