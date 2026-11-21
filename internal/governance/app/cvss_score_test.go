package app

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

const (
	sv65 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
	sv91 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
)

type scoreFindings struct {
	f   map[domain.FindingID]domain.Finding
	err error
}

func (s *scoreFindings) GetByID(_ context.Context, id domain.FindingID) (domain.Finding, error) {
	if s.err != nil {
		return domain.Finding{}, s.err
	}
	f, ok := s.f[id]
	if !ok {
		return domain.Finding{}, errors.New("not found")
	}
	return f, nil
}

type scoreRatings struct {
	c     []domain.ScoreCandidate
	err   error
	calls int
}

func (s *scoreRatings) SourceRatings(context.Context, string) ([]domain.ScoreCandidate, error) {
	s.calls++
	return s.c, s.err
}

type scoreKnowledge struct {
	k   FaultlineKnowledge
	err error
}

func (s *scoreKnowledge) GetFaultline(context.Context, string) (FaultlineKnowledge, error) {
	return s.k, s.err
}

type scoreReqs struct {
	r   domain.ScoreRequirements
	err error
}

func (s *scoreReqs) ResolvedRequirements(context.Context, string) (domain.ScoreRequirements, error) {
	return s.r, s.err
}

type memScores struct {
	comps   map[string][]ScoreRevision
	rollups map[string][]RollupRevision
	ids     []string
	readErr error
	listErr error
	histErr error
	appends int
}

func newMemScores() *memScores {
	return &memScores{comps: map[string][]ScoreRevision{}, rollups: map[string][]RollupRevision{}}
}

func (m *memScores) CurrentScores(_ context.Context, id string) ([]ScoreRevision, *RollupRevision, error) {
	if m.readErr != nil {
		return nil, nil, m.readErr
	}
	latest := map[string]ScoreRevision{}
	for _, r := range m.comps[id] {
		latest[r.PURL] = r
	}
	out := make([]ScoreRevision, 0, len(latest))
	for _, r := range latest {
		out = append(out, r)
	}
	var roll *RollupRevision
	if rs := m.rollups[id]; len(rs) > 0 {
		r := rs[len(rs)-1]
		roll = &r
	}
	return out, roll, nil
}

func (m *memScores) AppendScores(_ context.Context, id string, comps []ScoreRevision, rollup *RollupRevision) error {
	m.appends++
	for _, c := range comps {
		n := 0
		for _, p := range m.comps[id] {
			if p.PURL == c.PURL {
				n = p.Revision
			}
		}
		c.Revision = n + 1
		m.comps[id] = append(m.comps[id], c)
	}
	if rollup != nil {
		rollup.Revision = len(m.rollups[id]) + 1
		m.rollups[id] = append(m.rollups[id], *rollup)
	}
	return nil
}

func (m *memScores) ScoreHistory(_ context.Context, id string) ([]ScoreRevisionSummary, error) {
	if m.histErr != nil {
		return nil, m.histErr
	}
	var out []ScoreRevisionSummary
	for _, c := range m.comps[id] {
		out = append(out, ScoreRevisionSummary{PURL: c.PURL, Revision: c.Revision, Cause: c.Cause, Status: c.Snapshot.Status})
	}
	return out, nil
}

func (m *memScores) FindingIDsAfter(_ context.Context, after string, limit int) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	ids := append([]string(nil), m.ids...)
	sort.Strings(ids)
	var out []string
	for _, id := range ids {
		if id > after && len(out) < limit {
			out = append(out, id)
		}
	}
	return out, nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func scoreFinding(id string, comps ...domain.MatchedComponent) domain.Finding {
	return domain.ReconstituteFinding(domain.FindingID(id), "rel-1", "fl-1", "CVE-2026-0001", comps, domain.StageIdentified, nil, nil, 1)
}

var openssl = domain.MatchedComponent{PURL: "pkg:rpm/redhat/openssl@3.0.7-27.el9", Name: "openssl", Version: "3.0.7-27.el9", Ecosystem: "rpm"}

func scoreFixture() (*ScoreService, *memScores, *scoreRatings, *scoreFindings) {
	f := &scoreFindings{f: map[domain.FindingID]domain.Finding{"f1": scoreFinding("f1", openssl)}}
	r := &scoreRatings{c: []domain.ScoreCandidate{{RatingID: "a", Assessor: "x", Vector: sv65, Version: "3.1", InheritedContext: "openssl", Active: true}}}
	st := newMemScores()
	svc := NewScoreService(f, &scoreKnowledge{}, r, nil, st, fixedClock{time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)})
	return svc, st, r, f
}

func TestScoreAssessIdempotent(t *testing.T) {
	svc, st, r, _ := scoreFixture()
	ctx := context.Background()
	changed, err := svc.Assess(ctx, "f1")
	if err != nil || !changed {
		t.Fatalf("first assess: %v %v", changed, err)
	}
	if got := st.comps["f1"][0]; got.Cause != domain.CauseComponentAdded || got.Snapshot.Status != domain.ScoreFinal {
		t.Fatalf("revision %+v", got)
	}
	if st.rollups["f1"][0].Snapshot.State != domain.RollupScored || st.rollups["f1"][0].Cause != domain.CauseComponentAdded {
		t.Fatalf("rollup %+v", st.rollups["f1"][0])
	}
	// Same inputs again: nothing written (R-H2).
	changed, err = svc.Assess(ctx, "f1")
	if err != nil || changed || st.appends != 1 {
		t.Fatalf("re-delivery wrote: %v %v %d", changed, err, st.appends)
	}
	// A new source: new component revision, cause source_added; old kept.
	r.c = append(r.c, domain.ScoreCandidate{RatingID: "b", Assessor: "y", Vector: sv91, Version: "3.1", InheritedContext: "openssl", Active: true})
	if changed, err = svc.Assess(ctx, "f1"); err != nil || !changed {
		t.Fatal(err)
	}
	if len(st.comps["f1"]) != 2 || st.comps["f1"][1].Cause != domain.CauseSourceAdded || st.comps["f1"][1].Revision != 2 {
		t.Fatalf("revisions %+v", st.comps["f1"])
	}
	if st.comps["f1"][0].Snapshot.Status != domain.ScoreFinal {
		t.Error("old revision rewritten")
	}
	view, err := svc.Score(ctx, "f1")
	if err != nil || view.Rollup == nil || view.Rollup.Snapshot.Status != domain.ScoreProvisional || len(view.Components) != 1 || len(view.History) != 2 {
		t.Fatalf("view %+v %v", view, err)
	}
}

func TestScoreComponentRemoved(t *testing.T) {
	svc, st, _, f := scoreFixture()
	ctx := context.Background()
	other := domain.MatchedComponent{PURL: "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9", Name: "openssl-libs", Version: "3.0.7-27.el9"}
	f.f["f1"] = scoreFinding("f1", other, openssl)
	if _, err := svc.Assess(ctx, "f1"); err != nil {
		t.Fatal(err)
	}
	if v, _ := svc.Score(ctx, "f1"); len(v.Components) != 2 || v.Components[0].PURL != other.PURL {
		t.Fatalf("components not in purl order: %+v", v.Components)
	}
	retired := openssl
	retired.Retired = true
	f.f["f1"] = scoreFinding("f1", other, retired)
	if _, err := svc.Assess(ctx, "f1"); err != nil {
		t.Fatal(err)
	}
	rs := st.rollups["f1"]
	if len(rs) != 2 || rs[1].Cause != domain.CauseComponentRemoved || len(st.comps["f1"]) != 2 {
		t.Fatalf("rollups %+v comps %d", rs, len(st.comps["f1"]))
	}
	view, _ := svc.Score(ctx, "f1")
	if len(view.Components) != 1 || view.Components[0].PURL != other.PURL {
		t.Errorf("retired component served: %+v", view.Components)
	}
	// Removing the unassessed one is also a removal.
	f.f["f1"] = scoreFinding("f1", retired)
	_, _ = svc.Assess(ctx, "f1")
	if got := st.rollups["f1"][2]; got.Cause != domain.CauseComponentRemoved || got.Snapshot.State != domain.RollupNoComponents {
		t.Fatalf("rollup %+v", got)
	}
}

func TestScoreUnassessedRemoved(t *testing.T) {
	svc, st, r, f := scoreFixture()
	ctx := context.Background()
	r.c = nil // nothing scores: the component is unassessed
	other := domain.MatchedComponent{PURL: "pkg:npm/x@1", Name: "x"}
	f.f["f1"] = scoreFinding("f1", openssl, other)
	_, _ = svc.Assess(ctx, "f1")
	gone := other
	gone.Retired = true
	f.f["f1"] = scoreFinding("f1", openssl, gone)
	_, _ = svc.Assess(ctx, "f1")
	if got := st.rollups["f1"]; len(got) != 2 || got[1].Cause != domain.CauseComponentRemoved {
		t.Fatalf("rollups %+v", got)
	}
}

func TestScoreInputs(t *testing.T) {
	svc, st, _, _ := scoreFixture()
	ctx := context.Background()
	kn := &scoreKnowledge{k: FaultlineKnowledge{KEV: true, Fixes: []FixedVersion{{Package: "openssl", Version: "3.0.7-28.el9", Ecosystem: "rpm"}}}}
	reqs := &scoreReqs{r: domain.ScoreRequirements{CR: domain.RequirementValue{Value: "H", Level: "release"}}}
	svc.knowledge, svc.reqs = kn, reqs
	if _, err := svc.Assess(ctx, "f1"); err != nil {
		t.Fatal(err)
	}
	snap := st.comps["f1"][0].Snapshot
	if snap.Temporal[1].Used != "O" || snap.Temporal[0].State != domain.MetricProposed || snap.Requirements.CR.Value != "H" {
		t.Fatalf("snapshot %+v %+v", snap.Temporal, snap.Requirements)
	}
	// Without a Registry seam the requirements are X at level default.
	if d := defaultRequirements(); d.AR.Value != "X" || d.AR.Level != "default" {
		t.Error(d)
	}
	// A fix for another package is no RL:O evidence.
	if scoreComponent(openssl, FaultlineKnowledge{Fixes: []FixedVersion{{Package: "curl"}}}).FixApplicable {
		t.Error("unrelated fix used")
	}
}

func TestScoreReadFailures(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	cases := []struct {
		name string
		set  func(*ScoreService, *memScores, *scoreRatings, *scoreFindings)
	}{
		{"finding", func(_ *ScoreService, _ *memScores, _ *scoreRatings, f *scoreFindings) { f.err = boom }},
		{"ratings", func(_ *ScoreService, _ *memScores, r *scoreRatings, _ *scoreFindings) { r.err = boom }},
		{"knowledge", func(s *ScoreService, _ *memScores, _ *scoreRatings, _ *scoreFindings) { s.knowledge = &scoreKnowledge{err: boom} }},
		{"requirements", func(s *ScoreService, _ *memScores, _ *scoreRatings, _ *scoreFindings) { s.reqs = &scoreReqs{err: boom} }},
		{"store", func(_ *ScoreService, m *memScores, _ *scoreRatings, _ *scoreFindings) { m.readErr = boom }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, r, f := scoreFixture()
			tc.set(svc, st, r, f)
			if _, err := svc.Assess(ctx, "f1"); !errors.Is(err, boom) {
				t.Fatalf("err = %v", err)
			}
			if st.appends != 0 {
				t.Error("wrote from partial inputs")
			}
		})
	}
	for _, tc := range []struct {
		name string
		set  func(*memScores, *scoreFindings)
	}{
		{"finding", func(_ *memScores, f *scoreFindings) { f.err = boom }},
		{"current", func(m *memScores, _ *scoreFindings) { m.readErr = boom }},
		{"history", func(m *memScores, _ *scoreFindings) { m.histErr = boom }},
	} {
		svc, st, _, f := scoreFixture()
		tc.set(st, f)
		if _, err := svc.Score(ctx, "f1"); !errors.Is(err, boom) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}

func TestScoreSweep(t *testing.T) {
	svc, st, r, f := scoreFixture()
	ctx := context.Background()
	f.f["f2"] = scoreFinding("f2", openssl)
	f.f["f3"] = scoreFinding("f3", openssl)
	st.ids = []string{"f1", "f2", "f3", "missing"}
	sweep := NewScoreSweep(svc)
	sweep.page = 2
	res, err := sweep.Run(ctx)
	if err != nil || res.Assessed != 4 || res.Changed != 3 || res.Failed != 1 || res.FirstError == nil {
		t.Fatalf("res %+v err %v", res, err)
	}
	if r.calls != 1 {
		t.Errorf("ratings read %d times; one card is read once per run", r.calls)
	}
	res, _ = sweep.Run(ctx)
	if res.Changed != 0 {
		t.Errorf("second run changed %d", res.Changed)
	}
	st.listErr = errors.New("list")
	if _, err := sweep.Run(ctx); err == nil {
		t.Error("list failure swallowed")
	}
	st.listErr = nil
	// RunEvery runs once at start and stops with its context.
	cctx, cancel := context.WithCancel(ctx)
	runs := 0
	done := make(chan struct{})
	go func() {
		sweep.RunEvery(cctx, time.Millisecond, func(SweepResult, error) {
			runs++
			if runs == 2 {
				cancel()
			}
		})
		close(done)
	}()
	<-done
	if runs < 2 {
		t.Errorf("runs %d", runs)
	}
}
