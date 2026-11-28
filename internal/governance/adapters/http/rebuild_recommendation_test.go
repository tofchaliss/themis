package http_test

import (
	"context"
	"encoding/json"
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

type recStore struct {
	recs    map[string]app.RebuildRecommendation
	result  string
	writes  []app.RebuildApprovalWrite
	err     error
	expired int
}

func (s *recStore) RebuildRecommendation(_ context.Context, id string) (app.RebuildRecommendation, bool, error) {
	rec, ok := s.recs[id]
	return rec, ok, s.err
}

func (s *recStore) LatestRebuildRecommendation(_ context.Context, releaseID string) (app.RebuildRecommendation, bool, error) {
	for _, rec := range s.recs {
		if rec.Decision.ReleaseID == releaseID {
			return rec, true, s.err
		}
	}
	return app.RebuildRecommendation{}, false, s.err
}

func (s *recStore) RebuildRecommendationStatus(context.Context, string) (app.RebuildRecommendationStatus, error) {
	var out app.RebuildRecommendationStatus
	if rec, ok := s.recs["dec-1"]; ok && rec.State == domain.RebuildRecStanding {
		out.Standing = &rec
	}
	return out, nil
}

func (s *recStore) ApproveRebuildRecommendation(_ context.Context, in app.RebuildApprovalWrite) (string, error) {
	s.writes = append(s.writes, in)
	return s.result, nil
}

func (s *recStore) StandingRebuildRecommendationsBefore(context.Context, time.Time, int) ([]app.RebuildRecommendation, error) {
	return nil, nil
}

func (s *recStore) ExpireRebuildRecommendation(context.Context, string, time.Time, app.OutboxNote) (bool, error) {
	s.expired++
	return true, nil
}

type recIDs struct{}

func (recIDs) NewID() string { return "trig-1" }

// fixedClock in this package reads 2026-06-28 or similar; the recommendations below are dated
// relative to it.
func recommendationAt(id, state string, age time.Duration) app.RebuildRecommendation {
	at := fixedClock{}.Now().Add(-age)
	return app.RebuildRecommendation{State: state, StateAt: at, Decision: domain.RebuildDecision{
		DecisionID: id, ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "proj-1", Outcome: domain.RebuildOutcomeRecommend,
		RecommendReason: domain.RebuildRecommendModeAsk, DecidedAt: at, EffectiveMode: "ask", EffectiveModeSetBy: "installation",
		InstallationMode: "ask", Policy: domain.RebuildDecisionPolicy{ScopeKind: "installation", Mode: "ask"},
		Targeted: []domain.RebuildDecisionEntry{{FindingID: "f1", CVE: "CVE-2026-0001", PURL: "pkg:rpm/redhat/kernel@1",
			ScoreSource: "base_score", ClaimClass: "carrier", Position: "none", AssessmentState: "not_assessed"}},
	}}
}

// recServer wires the approval behind an injected principal (nil scopes = auth disabled).
// mode is the installation mode; tagsErr makes the Registry tag read fail.
func recServer(t *testing.T, st *recStore, mode domain.RebuildMode, tagsErr bool, scopes []string) *httptest.Server {
	t.Helper()
	repo := newRepo()
	h := govhttp.NewHandler(app.NewFindingService(repo, &seqIDs{}, fixedClock{}), app.NewReadService(repo, fakeProjection{}, nil, 0))
	if st != nil {
		tags := &evalTags{levels: map[string]app.ReleaseTagLevels{"rel-1": {ProductID: "prod-1", ProjectID: "proj-1", Release: []string{"rebuild:auto"}}}}
		if tagsErr {
			tags.levels = nil
		}
		policy := app.NewRebuildPolicyService(&memRebuild{}, fixedClock{}).WithTags(tags)
		p := domain.DefaultRebuildPolicy()
		p.Mode = mode
		if _, err := policy.PutInstallation(context.Background(), p, "alice"); err != nil {
			t.Fatal(err)
		}
		h = h.WithRebuildApproval(app.NewRebuildApprovalService(st, policy, recIDs{}, fixedClock{}))
	}
	router := h.Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scopes != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k", Name: "deciders", Scopes: scopes}))
		}
		router.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func approve(t *testing.T, srv *httptest.Server, id string, body any) (int, gen.RebuildApprovalAnswer) {
	t.Helper()
	code, raw := do(t, http.MethodPost, srv.URL+"/rebuild-recommendations/"+id+"/approve", body)
	var out gen.RebuildApprovalAnswer
	_ = json.Unmarshal(raw, &out)
	return code, out
}

var actorPat = map[string]any{"actor_id": "pat"}

// Step R4: the approval publishes the request and records who approved with which key.
func TestRebuildApproval_Approves(t *testing.T) {
	st := &recStore{recs: map[string]app.RebuildRecommendation{"dec-1": recommendationAt("dec-1", domain.RebuildRecStanding, time.Hour)},
		result: app.RebuildApprovalApproved}
	srv := recServer(t, st, domain.RebuildModeAsk, false, []string{auth.ProductScopePrefix + "prod-1"})
	code, ans := approve(t, srv, "dec-1", actorPat)
	if code != http.StatusOK || ans.Result != gen.RebuildApprovalAnswerResultApproved || ans.State != gen.RebuildApprovalAnswerStateApproved ||
		ans.DecisionId != "dec-1" || ans.ReleaseId != "rel-1" || ans.EffectiveMode == nil || *ans.EffectiveMode != gen.RebuildApprovalAnswerEffectiveModeAsk {
		t.Fatalf("answer %d %+v", code, ans)
	}
	if len(st.writes) != 1 || st.writes[0].Approval.Actor != "pat" || st.writes[0].Approval.KeyName != "deciders" ||
		len(st.writes[0].Approval.KeyScopes) != 1 || !st.writes[0].Approve {
		t.Fatalf("write = %+v", st.writes)
	}
}

// D22: admin or the key of the Release's own Product; never a read or a callback key, and
// never a key of another Product. Auth disabled (dev) lets the call through.
func TestRebuildApproval_WhoMayApprove(t *testing.T) {
	for name, tc := range map[string]struct {
		scopes []string
		want   int
	}{
		"admin":            {[]string{auth.ScopeAdmin}, http.StatusOK},
		"own product":      {[]string{auth.ProductScopePrefix + "prod-1"}, http.StatusOK},
		"auth disabled":    {nil, http.StatusOK},
		"other product":    {[]string{auth.ProductScopePrefix + "prod-9"}, http.StatusForbidden},
		"read key":         {[]string{auth.ScopeRead}, http.StatusForbidden},
		"callback key":     {[]string{auth.ScopeDeliveryCallback}, http.StatusForbidden},
		"no scope at all ": {[]string{}, http.StatusForbidden},
	} {
		st := &recStore{recs: map[string]app.RebuildRecommendation{"dec-1": recommendationAt("dec-1", domain.RebuildRecStanding, time.Hour)},
			result: app.RebuildApprovalApproved}
		code, _ := approve(t, recServer(t, st, domain.RebuildModeAsk, false, tc.scopes), "dec-1", actorPat)
		if code != tc.want || (tc.want != http.StatusOK && len(st.writes) != 0) {
			t.Errorf("%s: %d writes %d, want %d", name, code, len(st.writes), tc.want)
		}
	}
}

func TestRebuildApproval_Refusals(t *testing.T) {
	admin := []string{auth.ScopeAdmin}
	standing := func() *recStore {
		return &recStore{recs: map[string]app.RebuildRecommendation{"dec-1": recommendationAt("dec-1", domain.RebuildRecStanding, time.Hour)},
			result: app.RebuildApprovalApproved}
	}
	// No actor, or no body: 400, nothing written.
	st := standing()
	srv := recServer(t, st, domain.RebuildModeAsk, false, admin)
	for _, body := range []any{map[string]any{}, map[string]any{"actor_id": "  "}} {
		if code, _ := approve(t, srv, "dec-1", body); code != http.StatusBadRequest || len(st.writes) != 0 {
			t.Errorf("body %v: %d", body, code)
		}
	}
	if code, _ := doRaw(t, srv.URL+"/rebuild-recommendations/dec-1/approve", `{`); code != http.StatusBadRequest {
		t.Errorf("malformed body: %d", code)
	}
	if code, _ := approve(t, srv, "nope", actorPat); code != http.StatusNotFound {
		t.Errorf("unknown id: %d", code)
	}
	// The mode is no longer ask: 409 withdrawn, and the answer says which mode is in force.
	st = standing()
	st.result = app.RebuildApprovalWithdrawn
	code, ans := approve(t, recServer(t, st, domain.RebuildModeAuto, false, admin), "dec-1", actorPat)
	if code != http.StatusConflict || ans.Result != gen.RebuildApprovalAnswerResultWithdrawn || ans.EffectiveMode == nil || *ans.EffectiveMode != gen.RebuildApprovalAnswerEffectiveModeAuto {
		t.Errorf("withdrawn: %d %+v", code, ans)
	}
	// Not the standing one: 409 with the id of the one that is.
	st = standing()
	st.recs["dec-old"] = recommendationAt("dec-old", domain.RebuildRecSuperseded, 2*time.Hour)
	code, ans = approve(t, recServer(t, st, domain.RebuildModeAsk, false, admin), "dec-old", actorPat)
	if code != http.StatusConflict || ans.Result != gen.RebuildApprovalAnswerResultNotStanding || ans.StandingDecisionId == nil || *ans.StandingDecisionId != "dec-1" {
		t.Errorf("not standing: %d %+v", code, ans)
	}
	// Past its 7 days: 409 expired, recorded once.
	st = &recStore{recs: map[string]app.RebuildRecommendation{"dec-1": recommendationAt("dec-1", domain.RebuildRecStanding, domain.RebuildRecommendationTTL)}}
	code, ans = approve(t, recServer(t, st, domain.RebuildModeAsk, false, admin), "dec-1", actorPat)
	if code != http.StatusConflict || ans.Result != gen.RebuildApprovalAnswerResultExpired || st.expired != 1 {
		t.Errorf("expired: %d %+v", code, ans)
	}
	// Registry unread: 503, fail closed.
	st = standing()
	if code, _ := approve(t, recServer(t, st, domain.RebuildModeAsk, true, admin), "dec-1", actorPat); code != http.StatusServiceUnavailable || len(st.writes) != 0 {
		t.Errorf("tags unread: %d", code)
	}
	// The policy keeps changing: 503 try again.
	st = standing()
	st.result = app.RebuildApprovalWritePolicyChanged
	if code, _ := approve(t, recServer(t, st, domain.RebuildModeAsk, false, admin), "dec-1", actorPat); code != http.StatusServiceUnavailable {
		t.Errorf("busy: %d", code)
	}
	// Store fault: 500. Not wired: 503.
	st = standing()
	st.err = errors.New("db down")
	if code, _ := approve(t, recServer(t, st, domain.RebuildModeAsk, false, admin), "dec-1", actorPat); code != http.StatusInternalServerError {
		t.Errorf("store fault: %d", code)
	}
	if code, _ := approve(t, recServer(t, nil, domain.RebuildModeAsk, false, admin), "dec-1", actorPat); code != http.StatusServiceUnavailable {
		t.Errorf("not wired: %d", code)
	}
}

func TestRebuildRecommendation_Read(t *testing.T) {
	read := []string{auth.ScopeRead}
	standing := recommendationAt("dec-1", domain.RebuildRecStanding, time.Hour)
	standing.Decision.Supersedes = "dec-0"
	srv := recServer(t, &recStore{recs: map[string]app.RebuildRecommendation{"dec-1": standing}}, domain.RebuildModeAsk, false, read)
	code, got := getJSON[gen.RebuildRecommendation](t, srv.URL+"/releases/rel-1/rebuild-recommendation")
	if code != http.StatusOK || got.State != gen.Standing || !got.CanApprove || got.Approval != nil ||
		got.Decision.DecisionId != "dec-1" || got.Decision.Supersedes == nil || *got.Decision.Supersedes != "dec-0" ||
		!got.ExpiresAt.Equal(standing.Decision.DecidedAt.Add(domain.RebuildRecommendationTTL)) || len(got.Decision.Targeted) != 1 {
		t.Fatalf("standing: %d %+v", code, got)
	}
	// Past its time by the clock: served as expired even before the sweep recorded it.
	old := recommendationAt("dec-1", domain.RebuildRecStanding, domain.RebuildRecommendationTTL)
	srv = recServer(t, &recStore{recs: map[string]app.RebuildRecommendation{"dec-1": old}}, domain.RebuildModeAsk, false, read)
	if _, got := getJSON[gen.RebuildRecommendation](t, srv.URL+"/releases/rel-1/rebuild-recommendation"); got.State != gen.Expired || got.CanApprove {
		t.Errorf("by the clock: %+v", got)
	}
	// No build profile: standing, and not approvable.
	np := recommendationAt("dec-1", domain.RebuildRecStanding, time.Hour)
	np.Decision.RecommendReason = domain.RebuildRecommendNoBuildProfile
	srv = recServer(t, &recStore{recs: map[string]app.RebuildRecommendation{"dec-1": np}}, domain.RebuildModeAsk, false, read)
	if _, got := getJSON[gen.RebuildRecommendation](t, srv.URL+"/releases/rel-1/rebuild-recommendation"); got.CanApprove {
		t.Errorf("no profile must not be approvable: %+v", got)
	}
	// Approved and superseded ones carry what happened to them.
	approved := recommendationAt("dec-1", domain.RebuildRecApproved, time.Hour)
	approved.Approval = &domain.RebuildApproval{Actor: "pat", KeyName: "deciders", ApprovedAt: approved.StateAt,
		PolicyVersions: domain.RebuildPolicyVersions{Installation: 2, Product: 1}, Tag: "auto", TagLevel: "release", TagsReadAt: approved.StateAt}
	approved.CycleClosed, approved.SupersededBy = true, "dec-2"
	srv = recServer(t, &recStore{recs: map[string]app.RebuildRecommendation{"dec-1": approved}}, domain.RebuildModeAsk, false, read)
	_, got = getJSON[gen.RebuildRecommendation](t, srv.URL+"/releases/rel-1/rebuild-recommendation")
	if got.State != gen.Approved || got.CanApprove || got.Approval == nil || got.Approval.Actor != "pat" ||
		got.Approval.KeyScopes == nil || got.Approval.PolicyVersions.Installation != 2 || got.Approval.PolicyVersions.Product != 1 ||
		got.CycleClosed == nil || !*got.CycleClosed || got.SupersededBy == nil || *got.SupersededBy != "dec-2" {
		t.Errorf("approved: %+v", got)
	}
	if code, _ := do(t, http.MethodGet, srv.URL+"/releases/rel-none/rebuild-recommendation", nil); code != http.StatusNotFound {
		t.Errorf("no recommendation: %d", code)
	}
	failing := recServer(t, &recStore{err: errors.New("db down")}, domain.RebuildModeAsk, false, read)
	if code, _ := do(t, http.MethodGet, failing.URL+"/releases/rel-1/rebuild-recommendation", nil); code != http.StatusInternalServerError {
		t.Errorf("store fault: %d", code)
	}
	if code, _ := do(t, http.MethodGet, recServer(t, nil, domain.RebuildModeAsk, false, read).URL+"/releases/rel-1/rebuild-recommendation", nil); code != http.StatusServiceUnavailable {
		t.Errorf("not wired: %d", code)
	}
}
