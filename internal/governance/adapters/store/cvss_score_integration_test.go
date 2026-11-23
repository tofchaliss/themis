//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// TestScoreRevisionsAppendOnly drives the S4 store: revisions are numbered per component and per
// roll-up, the current one is the newest, nothing is updated, and the snapshot round-trips.
func TestScoreRevisionsAppendOnly(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

	comps, roll, err := st.CurrentScores(ctx, "f1")
	if err != nil || len(comps) != 0 || roll != nil {
		t.Fatalf("empty: %v %v %v", comps, roll, err)
	}
	score := 6.5
	snap := domain.ComponentScore{PURL: "pkg:npm/a@1", Status: domain.ScoreFinal, Scores: &domain.Scores{Environmental: 6.5}, Candidates: []domain.CandidateEvaluation{{RatingID: "r1", Disposition: domain.DispReference}}}
	first := []app.ScoreRevision{
		{PURL: "pkg:npm/a@1", Cause: domain.CauseComponentAdded, Fingerprint: "fa1", Snapshot: snap, RecordedAt: at},
		{PURL: "pkg:npm/b@1", Cause: domain.CauseComponentAdded, Fingerprint: "fb1", Snapshot: domain.ComponentScore{PURL: "pkg:npm/b@1", Status: domain.ScoreUnavailable}, RecordedAt: at},
	}
	r1 := &app.RollupRevision{Cause: domain.CauseComponentAdded, Fingerprint: "r1", Snapshot: domain.FindingScore{State: domain.RollupScored, Score: &score}, RecordedAt: at}
	if err := st.AppendScores(ctx, "f1", first, r1); err != nil {
		t.Fatal(err)
	}
	snap.Status = domain.ScoreProvisional
	if err := st.AppendScores(ctx, "f1", []app.ScoreRevision{{PURL: "pkg:npm/a@1", Cause: domain.CauseSourceAdded, Fingerprint: "fa2", Snapshot: snap, RecordedAt: at.Add(time.Hour)}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendScores(ctx, "f1", nil, &app.RollupRevision{Cause: domain.CauseSourceAdded, Fingerprint: "r2", Snapshot: domain.FindingScore{State: domain.RollupUnavailable}, RecordedAt: at.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	comps, roll, err = st.CurrentScores(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	cur := map[string]app.ScoreRevision{}
	for _, c := range comps {
		cur[c.PURL] = c
	}
	if a := cur["pkg:npm/a@1"]; a.Revision != 2 || a.Fingerprint != "fa2" || a.Snapshot.Status != domain.ScoreProvisional || a.Snapshot.Candidates[0].RatingID != "r1" {
		t.Errorf("current a = %+v", a)
	}
	if b := cur["pkg:npm/b@1"]; b.Revision != 1 {
		t.Errorf("current b = %+v", b)
	}
	if roll == nil || roll.Revision != 2 || roll.Snapshot.State != domain.RollupUnavailable || !roll.RecordedAt.Equal(at.Add(time.Hour)) {
		t.Errorf("rollup = %+v", roll)
	}
	hist, err := st.ScoreHistory(ctx, "f1")
	if err != nil || len(hist) != 3 || hist[0].Cause != domain.CauseSourceAdded || hist[0].Score == nil || *hist[0].Score != 6.5 {
		t.Fatalf("history %+v %v", hist, err)
	}
	if n := count(t, pool, `SELECT count(*) FROM component_score_revisions WHERE finding_id = 'f1'`); n != 3 {
		t.Errorf("revisions = %d", n)
	}
}

func TestFindingIDsAfter(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	for _, id := range []string{"c", "a", "b"} {
		if err := st.Save(ctx, newFinding(t, id, "rel", "fl-"+id, "CVE-2026-0001"), true, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := st.FindingIDsAfter(ctx, "", 2)
	if err != nil || len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("page 1 %v %v", ids, err)
	}
	ids, _ = st.FindingIDsAfter(ctx, "b", 2)
	if len(ids) != 1 || ids[0] != "c" {
		t.Fatalf("page 2 %v", ids)
	}
}

// TestPostureCarriesBothSeverities: the release posture reads the newest assessment — the
// roll-up's score as the expert severity, the source Base score over the same open carriers as
// the original — and a retired or superseded revision never counts (EDR-GUI-02 D13 amendment).
func TestPostureCarriesBothSeverities(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	at := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

	seed := func(id string, purls ...string) {
		f := newFinding(t, id, "rel-s", "fl-"+id, "CVE-"+id)
		for _, p := range purls {
			if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: p, Name: p, Version: "1"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.Save(ctx, f, true, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	seed("a", "pkg:a@1", "pkg:b@1")
	seed("c", "pkg:c@1")
	seed("n") // no assessment at all

	comp := func(purl string, open bool, base, env float64) app.ScoreRevision {
		return app.ScoreRevision{PURL: purl, Cause: domain.CauseComponentAdded, Fingerprint: purl, RecordedAt: at,
			Snapshot: domain.ComponentScore{PURL: purl, Eligible: true, Open: open, Status: domain.ScoreFinal, Scores: &domain.Scores{Base: base, Environmental: env}}}
	}
	expert := 5.5
	// Finding a: an old revision of pkg:a said 9.9; the newest says 8.1 → original 8.1, expert 5.5.
	if err := st.AppendScores(ctx, "a", []app.ScoreRevision{comp("pkg:a@1", true, 9.9, 9.9)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendScores(ctx, "a", []app.ScoreRevision{comp("pkg:a@1", true, 8.1, 5.5), comp("pkg:b@1", true, 6.0, 4.0)},
		&app.RollupRevision{Cause: domain.CauseComponentAdded, Fingerprint: "ra", RecordedAt: at,
			Snapshot: domain.FindingScore{State: domain.RollupScored, Score: &expert, Status: domain.ScoreProvisional}}); err != nil {
		t.Fatal(err)
	}
	// Finding c: its only carrier is cleared, so nothing is scored; the original falls back to it.
	if err := st.AppendScores(ctx, "c", []app.ScoreRevision{comp("pkg:c@1", false, 7.3, 7.3)},
		&app.RollupRevision{Cause: domain.CauseComponentAdded, Fingerprint: "rc", RecordedAt: at,
			Snapshot: domain.FindingScore{State: domain.RollupNoOpenOccurrences}}); err != nil {
		t.Fatal(err)
	}

	posture, err := st.ReleasePosture(ctx, "rel-s")
	if err != nil || len(posture) != 3 {
		t.Fatalf("posture = %+v err=%v", posture, err)
	}
	by := map[string]app.PostureEntry{}
	for _, p := range posture {
		by[string(p.FindingID)] = p
	}
	if a := by["a"]; a.OriginalScore == nil || *a.OriginalScore != 8.1 || a.ExpertScore == nil || *a.ExpertScore != 5.5 ||
		a.ExpertStatus != domain.ScoreProvisional || a.ScoreState != domain.RollupScored {
		t.Errorf("a = %+v", a)
	}
	if c := by["c"]; c.OriginalScore == nil || *c.OriginalScore != 7.3 || c.ExpertScore != nil || c.ScoreState != domain.RollupNoOpenOccurrences {
		t.Errorf("c = %+v", c)
	}
	if n := by["n"]; n.OriginalScore != nil || n.ExpertScore != nil || n.ScoreState != "" {
		t.Errorf("n = %+v", n)
	}
}
