package http_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

type evalTags struct {
	levels map[string]app.ReleaseTagLevels
}

func (e evalTags) ReleaseTagLevels(_ context.Context, releaseID string) (app.ReleaseTagLevels, error) {
	l, ok := e.levels[releaseID]
	if !ok {
		return app.ReleaseTagLevels{}, errors.New("no such release")
	}
	return l, nil
}

type evalFacts struct {
	rows []app.RebuildFindingFacts
	err  error
}

func (e evalFacts) RebuildFacts(context.Context, string) ([]app.RebuildFindingFacts, error) {
	return e.rows, e.err
}

type evalFixes struct{ rows []app.ReleaseFixVerdict }

func (e evalFixes) ReleaseFixVerdicts(context.Context, string) ([]app.ReleaseFixVerdict, error) {
	return e.rows, nil
}

// evalServer wires the policy read and the judgement over one in-memory policy store. tags nil
// = no Registry seam for tags (the policy service then has no effective mode).
func evalServer(t *testing.T, st *memRebuild, tags *evalTags, facts evalFacts, fixes app.ReleaseFixVerdictReader, wireEval bool) *httptest.Server {
	t.Helper()
	repo := newRepo()
	h := govhttp.NewHandler(app.NewFindingService(repo, &seqIDs{}, fixedClock{}), app.NewReadService(repo, fakeProjection{}, nil, 0))
	svc := app.NewRebuildPolicyService(st, fixedClock{}).
		WithIdentity(rebuildOwners{byRelease: map[string]string{"rel-1": "prod-1"}})
	if tags != nil {
		svc = svc.WithTags(*tags)
	}
	h = h.WithRebuildPolicy(svc)
	if wireEval {
		h = h.WithRebuildEvaluation(app.NewRebuildEvaluationService(svc, facts, fixes, fixedClock{}))
	}
	router := h.Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k", Name: "t", Scopes: []string{auth.ScopeAdmin}}))
		router.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func evalFixture() (evalFacts, evalFixes) {
	open := func(purl, version, class string) domain.MatchedComponent {
		return domain.MatchedComponent{PURL: purl, Version: version, ClaimClass: class, VerdictState: "open"}
	}
	facts := evalFacts{rows: []app.RebuildFindingFacts{
		{FindingID: "f1", FaultlineID: "fl-1", CVE: "CVE-2026-0001", Stage: "triage", BaseScore: 80,
			Components: []domain.MatchedComponent{open("pkg:rpm/redhat/kernel@4.18.0-1.el8", "4.18.0-1.el8", "carrier")}},
		{FindingID: "f2", FaultlineID: "fl-2", CVE: "CVE-2026-0002", Stage: "triage", BaseScore: 95, Stance: domain.StanceAcceptedRisk,
			Components: []domain.MatchedComponent{open("pkg:rpm/redhat/zlib@1.2-1.el8", "1.2-1.el8", "")}},
		{FindingID: "f3", FaultlineID: "fl-3", CVE: "CVE-2026-0003", Stage: "triage", BaseScore: 95,
			Components: []domain.MatchedComponent{open("pkg:npm/left-pad@1.0.0", "1.0.0", "")}},
	}}
	fixes := evalFixes{rows: []app.ReleaseFixVerdict{
		{FaultlineID: "fl-1", PURL: "pkg:rpm/redhat/kernel@4.18.0-1.el8", Fix: domain.RebuildFixKnown, FixedVersions: []string{"0:4.18.0-2.el8"}},
		{FaultlineID: "fl-2", PURL: "pkg:rpm/redhat/zlib@1.2-1.el8", Fix: domain.RebuildFixKnown, FixedVersions: []string{"0:1.2-9.el8"}},
	}}
	return facts, fixes
}

// Step R2 part 1: the read shows the judgement whole — the policy, the tag, the effective mode,
// the outcome, each counted component with its D34 facts, and what was left out and why.
func TestRebuildEvaluation_Read(t *testing.T) {
	facts, fixes := evalFixture()
	tags := &evalTags{levels: map[string]app.ReleaseTagLevels{
		"rel-1": {ProductID: "prod-1", ProjectID: "proj-1", Project: []string{"rebuild:auto"}},
	}}
	srv := evalServer(t, &memRebuild{}, tags, facts, fixes, true)

	code, got := getJSON[gen.RebuildEvaluation](t, srv.URL+"/releases/rel-1/rebuild-evaluation")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if got.ReleaseId != "rel-1" || got.ProductId != "prod-1" || got.ProjectId != "proj-1" || got.Outcome != "recommend" ||
		got.EffectiveMode != "ask" || got.EffectiveModeSetBy != "installation" || got.ModeCeiling != "ask" ||
		got.InstallationMode != "ask" || got.Tag.Mode != "auto" || got.Tag.Tag == nil || *got.Tag.Tag != "rebuild:auto" ||
		got.Tag.Level == nil || *got.Tag.Level != "project" || !got.FixVerdictsRead || got.Considered != 3 ||
		got.Policy.ScopeKind != "installation" || got.EvaluatedAt.IsZero() {
		t.Fatalf("judgement = %+v", got)
	}
	if got.Skipped.Decided != 1 || got.Skipped.FixUnknown != 1 || got.Skipped.NoFix != 0 || got.Skipped.ScopeComponent != 0 || got.Skipped.BelowFloor != 0 {
		t.Errorf("skipped = %+v", got.Skipped)
	}
	if len(got.Targeted) != 1 {
		t.Fatalf("targeted = %+v", got.Targeted)
	}
	e := got.Targeted[0]
	if e.FindingId != "f1" || e.Cve != "CVE-2026-0001" || e.Purl != "pkg:rpm/redhat/kernel@4.18.0-1.el8" || e.CurrentVersion != "4.18.0-1.el8" ||
		len(e.FixedVersions) != 1 || e.FixedVersions[0] != "0:4.18.0-2.el8" || e.FixSource == nil || *e.FixSource != "knowledge_verdict" ||
		e.Severity != "high" || e.Score != 80 || e.ScoreSource != "base_score" || e.KnownExploited || e.ClaimClass != "carrier" ||
		e.Position != "none" || len(e.CountedBecause) != 1 || e.CountedBecause[0] != "severity_floor" || e.Assessment.State != "not_assessed" {
		t.Errorf("entry = %+v", e)
	}

	// The in-force read now answers the effective mode too.
	code, inForce := getJSON[gen.RebuildPolicyInForce](t, srv.URL+"/releases/rel-1/rebuild-policy/in-force")
	if code != http.StatusOK || !inForce.TagsApplied || inForce.EffectiveMode == nil || *inForce.EffectiveMode != "ask" ||
		inForce.EffectiveModeSetBy == nil || *inForce.EffectiveModeSetBy != "installation" || inForce.Tag == nil ||
		inForce.Tag.Mode != "auto" || inForce.ProjectId == nil || *inForce.ProjectId != "proj-1" {
		t.Errorf("in force = %d %+v", code, inForce)
	}
}

// With fix_required and carrier_only off, a decided-open component with no fix and a scope
// component both count: the wire then says `scope`, `unknown`, the stance, an empty fix list
// and no fix source. A Release with no rebuild tag reads `none` with no tag named.
func TestRebuildEvaluation_LoosePolicyAndNoTag(t *testing.T) {
	st := &memRebuild{}
	tags := &evalTags{levels: map[string]app.ReleaseTagLevels{"rel-1": {ProductID: "prod-1", ProjectID: "proj-1"}}}
	facts := evalFacts{rows: []app.RebuildFindingFacts{
		{FindingID: "f1", FaultlineID: "fl-1", CVE: "CVE-2026-0001", Stage: "triage", BaseScore: 95, OwnerSet: true, KnownExploited: true, Stance: domain.StanceAffected,
			Components: []domain.MatchedComponent{
				{PURL: "pkg:rpm/redhat/python3-libs@3.6-1.el8", Version: "3.6-1.el8", ClaimClass: domain.ClaimScope},
				{PURL: "pkg:rpm/redhat/python3@3.6-1.el8", Version: "3.6-1.el8", ClaimClass: "odd"},
			}},
	}}
	srv := evalServer(t, st, tags, facts, nil, true)
	body := rebuildBody()
	body["fix_required"], body["carrier_only"], body["count_known_exploited"] = false, false, true
	if code, raw := do(t, http.MethodPut, srv.URL+"/rebuild-policy", body); code != http.StatusOK {
		t.Fatalf("PUT: %d %s", code, raw)
	}
	code, got := getJSON[gen.RebuildEvaluation](t, srv.URL+"/releases/rel-1/rebuild-evaluation")
	if code != http.StatusOK || got.Outcome != "none" || got.EffectiveMode != "off" || got.EffectiveModeSetBy != "tag" ||
		got.Tag.Mode != "off" || got.Tag.Tag != nil || got.Tag.Level != nil || got.FixVerdictsRead || len(got.Targeted) != 2 {
		t.Fatalf("judgement = %d %+v", code, got)
	}
	scope, odd := got.Targeted[0], got.Targeted[1]
	if scope.ClaimClass != "scope" || scope.Assessment.State != "not_eligible" || scope.FixSource != nil || scope.FixedVersions == nil ||
		len(scope.FixedVersions) != 0 || scope.Position != "affected" || scope.ScoreSource != "owner_set" || len(scope.CountedBecause) != 2 {
		t.Errorf("scope entry = %+v", scope)
	}
	if odd.ClaimClass != "unknown" || odd.Assessment.State != "not_assessed" {
		t.Errorf("odd entry = %+v", odd)
	}
}

func TestRebuildEvaluation_Refusals(t *testing.T) {
	facts, fixes := evalFixture()
	tags := &evalTags{levels: map[string]app.ReleaseTagLevels{"rel-1": {ProductID: "prod-1", ProjectID: "proj-1"}}}
	get := func(srv *httptest.Server, release string) int {
		code, _ := do(t, http.MethodGet, srv.URL+"/releases/"+release+"/rebuild-evaluation", nil)
		return code
	}
	if code := get(evalServer(t, &memRebuild{}, tags, facts, fixes, false), "rel-1"); code != http.StatusServiceUnavailable {
		t.Errorf("not wired: %d", code)
	}
	if code := get(evalServer(t, &memRebuild{}, nil, facts, fixes, true), "rel-1"); code != http.StatusServiceUnavailable {
		t.Errorf("no tag reader: %d", code)
	}
	if code := get(evalServer(t, &memRebuild{}, tags, facts, fixes, true), "rel-x"); code != http.StatusServiceUnavailable {
		t.Errorf("tags unreadable: %d", code)
	}
	if code := get(evalServer(t, &memRebuild{}, tags, evalFacts{err: errors.New("db down")}, fixes, true), "rel-1"); code != http.StatusInternalServerError {
		t.Errorf("store down: %d", code)
	}
}
