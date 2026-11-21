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
