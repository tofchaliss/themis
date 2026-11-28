//go:build integration

package store_test

import (
	"context"
	"encoding/json"
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
