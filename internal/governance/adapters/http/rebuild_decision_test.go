package http_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

type decisionStore struct {
	records []app.RebuildTriggerRecord
	err     error
	limit   int
}

func (*decisionStore) PendingRebuildTriggers(context.Context, int) ([]app.RebuildTrigger, error) {
	return nil, nil
}

func (*decisionStore) SettleRebuildTrigger(context.Context, app.RebuildTrigger, app.RebuildTriggerResult, *domain.RebuildDecision, app.OutboxNote) error {
	return nil
}

func (d *decisionStore) RebuildTriggerRecords(_ context.Context, _ string, limit int) ([]app.RebuildTriggerRecord, error) {
	d.limit = limit
	return d.records, d.err
}

func (*decisionStore) RebuildRecommendationStatus(context.Context, string) (app.RebuildRecommendationStatus, error) {
	return app.RebuildRecommendationStatus{}, nil
}

func (*decisionStore) ExpireRebuildRecommendation(context.Context, string, time.Time, app.OutboxNote) (bool, error) {
	return false, nil
}

func decisionServer(t *testing.T, st *decisionStore) *httptest.Server {
	t.Helper()
	repo := newRepo()
	h := govhttp.NewHandler(app.NewFindingService(repo, &seqIDs{}, fixedClock{}), app.NewReadService(repo, fakeProjection{}, nil, 0))
	if st != nil {
		h = h.WithRebuildDecisions(app.NewRebuildDecisionReader(st))
	}
	router := h.Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k", Name: "t", Scopes: []string{auth.ScopeRead}}))
		router.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Step R2 part 2: the read shows every trigger of the Release and how it ended. One still
// open, one closed with a reason, one closed with a decision and its frozen facts.
func TestRebuildDecisions_Read(t *testing.T) {
	at := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	entry := domain.RebuildDecisionEntry{
		FindingID: "f1", CVE: "CVE-2026-0001", PURL: "pkg:rpm/redhat/kernel@4.18.0-1.el8", CurrentVersion: "4.18.0-1.el8",
		FixedVersions: []string{"0:4.18.0-2.el8"}, FixSource: app.RebuildFixSourceVerdict, Severity: domain.SLABucketHigh,
		Score: 80, ScoreSource: app.RebuildScoreSourceBase, ClaimClass: "carrier", Position: "none",
		AssessmentState: app.RebuildAssessmentNotAssessed, CountedBecause: []string{domain.RebuildCountedSeverityFloor},
	}
	noFix := entry
	noFix.FindingID, noFix.FixedVersions, noFix.FixSource = "f2", nil, ""
	decision := &domain.RebuildDecision{
		DecisionID: "dec-1", ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "proj-1",
		TriggerID: "evt-3", TriggerSource: "governance", TriggerType: domain.RebuildTriggerFixAvailable,
		Outcome: domain.RebuildOutcomeRecommend, EffectiveMode: "ask", EffectiveModeSetBy: "installation",
		InstallationMode: "ask", Tag: domain.RebuildTagAuto, TagLevel: domain.RebuildTagLevelProject,
		Policy: domain.RebuildDecisionPolicy{ScopeKind: "product", ScopeID: "prod-1", Version: 3, FixRequired: true,
			SeverityFloor: domain.SLABucketHigh, CountKnownExploited: true, SkipDecided: true, CarrierOnly: true,
			CoolDownSeconds: 3600, Mode: "ask"},
		Considered: 4, Targeted: []domain.RebuildDecisionEntry{entry, noFix}, OtherStream: []domain.RebuildDecisionEntry{},
		DecidedAt: at,
	}
	// A decision with no build profile: a recommendation that says so, and no build.
	bare := *decision
	bare.DecisionID, bare.RecommendReason = "dec-0", domain.RebuildRecommendNoBuildProfile
	decision.RecommendReason = domain.RebuildRecommendModeAsk
	decision.Build = []byte(`{"image":"registry.example/app"}`)
	decision.BuildProfile = &domain.RebuildDecisionBuildProfile{Scope: "release", Revision: 2, SHA256: "abc123"}
	trig := func(id, typ string) app.RebuildTrigger {
		return app.RebuildTrigger{TriggerID: id, Source: "governance", Type: typ, ReleaseID: "rel-1", ReceivedAt: at}
	}
	st := &decisionStore{records: []app.RebuildTriggerRecord{
		{RebuildTrigger: trig("evt-3", domain.RebuildTriggerFixAvailable), Settled: true, Decision: decision,
			Result: app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeRecommend, EffectiveMode: "ask", ModeSetBy: "installation",
				Considered: 4, Targeted: 2, SettledAt: at}},
		{RebuildTrigger: trig("evt-2", domain.RebuildTriggerNewSBOM), Settled: true,
			Result: app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeNone, Reason: domain.RebuildNoneGaveUp, SettledAt: at}},
		{RebuildTrigger: trig("evt-1", domain.RebuildTriggerNewSBOM)},
		{RebuildTrigger: trig("evt-0", domain.RebuildTriggerNewSBOM), Settled: true, Decision: &bare,
			Result: app.RebuildTriggerResult{Outcome: domain.RebuildOutcomeRecommend, SettledAt: at}},
	}}
	srv := decisionServer(t, st)

	code, got := getJSON[gen.RebuildTriggerList](t, srv.URL+"/releases/rel-1/rebuild-decisions?limit=7")
	if code != http.StatusOK || len(got.Items) != 4 || st.limit != 7 {
		t.Fatalf("code %d items %d limit %d", code, len(got.Items), st.limit)
	}
	a := got.Items[0]
	if !a.Settled || a.Outcome == nil || string(*a.Outcome) != "recommend" || a.Reason != nil || a.SettledAt == nil ||
		a.EffectiveMode == nil || string(*a.EffectiveMode) != "ask" || string(*a.EffectiveModeSetBy) != "installation" ||
		a.TargetedCount != 2 || a.Considered != 4 || string(a.TriggerType) != "fix_available" || a.TriggerId != "evt-3" ||
		a.Decision == nil {
		t.Fatalf("decided trigger = %+v", a)
	}
	d := a.Decision
	if d.DecisionId != "dec-1" || string(d.Outcome) != "recommend" || d.ProductId != "prod-1" || d.ProjectId != "proj-1" ||
		d.Tag != "rebuild:auto" || d.TagLevel != "project" || string(d.Policy.ScopeKind) != "product" || d.Policy.ScopeId != "prod-1" ||
		d.Policy.Version != 3 || !d.Policy.FixRequired || d.Policy.CoolDownSeconds != 3600 || string(d.Policy.Mode) != "ask" ||
		d.Skipped == nil || len(d.Targeted) != 2 || len(d.OtherStream) != 0 || d.OtherStream == nil {
		t.Fatalf("decision = %+v", d)
	}
	if d.RecommendReason == nil || string(*d.RecommendReason) != "mode_ask" || d.Build == nil ||
		string(*d.Build) != `{"image":"registry.example/app"}` || d.BuildProfile == nil ||
		string(d.BuildProfile.Scope) != "release" || d.BuildProfile.Revision != 2 || d.BuildProfile.Sha256 != "abc123" {
		t.Errorf("build of the decision = %+v", d)
	}
	if n := got.Items[3].Decision; n == nil || n.RecommendReason == nil || string(*n.RecommendReason) != "no_build_profile" ||
		n.Build != nil || n.BuildProfile != nil {
		t.Errorf("decision without a profile = %+v", n)
	}
	if e := d.Targeted[0]; e.FindingId != "f1" || e.FixSource == nil || *e.FixSource != app.RebuildFixSourceVerdict ||
		len(e.FixedVersions) != 1 || string(e.Assessment.State) != "not_assessed" || len(e.CountedBecause) != 1 || e.Position != "none" {
		t.Errorf("entry = %+v", e)
	}
	if e := d.Targeted[1]; e.FixSource != nil || e.FixedVersions == nil || len(e.FixedVersions) != 0 {
		t.Errorf("entry without a fix = %+v", e)
	}
	b := got.Items[1]
	if !b.Settled || string(*b.Outcome) != "none" || b.Reason == nil || string(*b.Reason) != "gave_up" ||
		b.EffectiveMode != nil || b.Decision != nil {
		t.Errorf("gave-up trigger = %+v", b)
	}
	c := got.Items[2]
	if c.Settled || c.Outcome != nil || c.SettledAt != nil || c.Decision != nil || c.TriggerId != "evt-1" {
		t.Errorf("open trigger = %+v", c)
	}
}

func TestRebuildDecisions_UnwiredAndStoreError(t *testing.T) {
	get := func(srv *httptest.Server) int {
		res, err := http.Get(srv.URL + "/releases/rel-1/rebuild-decisions")
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	if code := get(decisionServer(t, nil)); code != http.StatusServiceUnavailable {
		t.Errorf("unwired = %d", code)
	}
	st := &decisionStore{err: errors.New("db down")}
	if code := get(decisionServer(t, st)); code != http.StatusInternalServerError || st.limit != app.RebuildDecisionsDefaultLimit {
		t.Errorf("store error = %d limit %d", code, st.limit)
	}
}
