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

// Owner-set severity (EDR-SCORING-01 section 7.1): the record is append-only, the read columns
// drive priority, the deadline bucket and the counts, and removal brings the original back.
func TestOwnerSeverityRecordAndReadColumns(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	at := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	who := domain.Actor{Kind: domain.ActorHuman, ID: "key:k-1"}

	seed := func(id, fl string, purls ...string) {
		t.Helper()
		f := newFinding(t, id, "rel-o", fl, "CVE-2026-O")
		for _, p := range purls {
			if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: p, Name: p, Version: "1"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.Save(ctx, f, true, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	seed("a", "fl-a", "pkg:a@1", "pkg:b@1")
	seed("b", "fl-b", "pkg:c@1")
	seed("n", "fl-n")
	// The original: critical (95 on the 0-100 scale) on a and b.
	for _, fl := range []string{"fl-a", "fl-b"} {
		if err := st.SetBaseScore(ctx, fl, 95); err != nil {
			t.Fatal(err)
		}
	}
	comp := func(purl string, eligible, open bool, base float64, vector string) app.ScoreRevision {
		return app.ScoreRevision{PURL: purl, Cause: domain.CauseComponentAdded, Fingerprint: purl, RecordedAt: at,
			Snapshot: domain.ComponentScore{PURL: purl, Eligible: eligible, Open: open, Status: domain.ScoreFinal,
				Scores: &domain.Scores{Base: base, Environmental: base}, AssessmentVector: vector}}
	}
	// Finding a: the open carrier (7.5) gives the original, not the higher scope-only one (9.8).
	if err := st.AppendScores(ctx, "a", []app.ScoreRevision{
		comp("pkg:a@1", true, true, 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
		comp("pkg:b@1", false, true, 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
	}, nil); err != nil {
		t.Fatal(err)
	}

	originals, err := st.OriginalSeverities(ctx, []domain.FindingID{"a", "b", "n"})
	if err != nil || len(originals) != 1 {
		t.Fatalf("originals = %+v %v", originals, err)
	}
	if o := originals["a"]; o.Score == nil || *o.Score != 7.5 || o.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" {
		t.Fatalf("original of a = %+v", o)
	}
	if none, err := st.OriginalSeverities(ctx, nil); err != nil || len(none) != 0 {
		t.Fatalf("no ids = %+v %v", none, err)
	}
	if none, err := st.CurrentOwnerSeverities(ctx, nil); err != nil || len(none) != 0 {
		t.Fatalf("no ids = %+v %v", none, err)
	}

	low, err := domain.NewOwnerSeverity("low", "", originals["a"].Score, "not reachable", who, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveOwnerSeverities(ctx, []app.OwnerSeverityWrite{
		{FindingID: "a", Severity: low}, {FindingID: "b", Severity: low.For("a", nil)},
	}); err != nil {
		t.Fatal(err)
	}
	current, err := st.CurrentOwnerSeverities(ctx, []domain.FindingID{"a", "b", "n"})
	if err != nil || len(current) != 2 {
		t.Fatalf("current = %+v %v", current, err)
	}
	if a := current["a"]; a.Kind != domain.OwnerSeverityByLevel || a.Level != domain.SeverityLow || a.Score != 3.9 || a.Vector != "" ||
		a.OriginalScore == nil || *a.OriginalScore != 7.5 || a.Reason != "not reachable" || a.Actor != who || !a.SetAt.Equal(at) || a.PickedFrom != "" {
		t.Fatalf("a = %+v", a)
	}
	if b := current["b"]; b.Score != 0.1 || b.OriginalScore != nil || b.PickedFrom != "a" {
		t.Fatalf("b = %+v", b)
	}

	// The lists read the owner-set score: 3.9 is 39 on the 0-100 scale, bucket low.
	byID := func() map[string]app.PostureEntry {
		t.Helper()
		posture, err := st.ReleasePosture(ctx, "rel-o")
		if err != nil || len(posture) != 3 {
			t.Fatalf("posture = %+v %v", posture, err)
		}
		out := map[string]app.PostureEntry{}
		for _, p := range posture {
			out[string(p.FindingID)] = p
		}
		return out
	}
	rows := byID()
	if a := rows["a"]; a.BaseScore != 39 || a.OwnerSeverity == nil || a.OwnerSeverity.Score != 3.9 || a.OriginalScore == nil || *a.OriginalScore != 7.5 {
		t.Fatalf("posture a = %+v", a)
	}
	if n := rows["n"]; n.OwnerSeverity != nil {
		t.Fatalf("posture n = %+v", n)
	}
	counts, err := st.CountFindingsByBaseScoreBuckets(ctx, "rel-o")
	if err != nil || counts.Critical != 0 || counts.Low != 2 {
		t.Fatalf("counts = %+v %v", counts, err)
	}
	slaOf := func() map[domain.FindingID]domain.SLAInput {
		t.Helper()
		facts, err := st.SLAFactsForRelease(ctx, "rel-o")
		if err != nil {
			t.Fatal(err)
		}
		out := map[domain.FindingID]domain.SLAInput{}
		for _, f := range facts {
			out[f.FindingID] = f.Input
		}
		return out
	}
	if in := slaOf()["a"]; in.Bucket != domain.SLABucketLow || in.CurrentBucket != domain.SLABucketLow {
		t.Fatalf("deadline bucket of a = %+v", in)
	}
	metrics, err := st.MetricsFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range metrics {
		if m.FindingID == "a" && m.Finding.Bucket != domain.SLABucketLow {
			t.Fatalf("metrics bucket of a = %q", m.Finding.Bucket)
		}
	}

	// A changed vector replaces the level: the first record is ended, never rewritten.
	vec, err := domain.NewOwnerSeverity("", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", originals["a"].Score, "needs a login", who, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	vec.OriginalVector = originals["a"].Vector
	if err := st.SaveOwnerSeverities(ctx, []app.OwnerSeverityWrite{{FindingID: "a", Severity: vec}}); err != nil {
		t.Fatal(err)
	}
	history, err := st.OwnerSeverityHistory(ctx, "a")
	if err != nil || len(history) != 2 {
		t.Fatalf("history = %+v %v", history, err)
	}
	if h := history[0]; h.EndCause != "replaced" || !h.EndedAt.Equal(at.Add(time.Hour)) || h.EndedBy != who.ID || h.Score != 3.9 {
		t.Fatalf("first record = %+v", h)
	}
	if h := history[1]; !h.EndedAt.IsZero() || h.Kind != domain.OwnerSeverityByVector || h.Score != 8.1 || h.Vector == "" {
		t.Fatalf("second record = %+v", h)
	}
	if a := byID()["a"]; a.BaseScore != 81 {
		t.Fatalf("posture a after the vector = %+v", a)
	}

	// OS6: the severity on a was set against an original of 7.5 with its vector. Nothing changed
	// yet, so the list shows no review; then the source corrects the rating.
	if a := byID()["a"]; a.SeverityReview != "" || a.OwnerSeverity.OriginalVector != originals["a"].Vector {
		t.Fatalf("fresh severity: review %q, vector %q", a.SeverityReview, a.OwnerSeverity.OriginalVector)
	}
	if err := st.AppendScores(ctx, "a", []app.ScoreRevision{
		{PURL: "pkg:a@1", Cause: domain.CauseSourceAdded, Fingerprint: "a-2", RecordedAt: at.Add(90 * time.Minute),
			Snapshot: domain.ComponentScore{PURL: "pkg:a@1", Eligible: true, Open: true, Status: domain.ScoreFinal,
				Scores: &domain.Scores{Base: 5.3, Environmental: 5.3}}},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if a := byID()["a"]; a.SeverityReview != "the original score changed from 7.5 to 5.3" || a.BaseScore != 81 {
		t.Fatalf("after the source change: review %q base %d", a.SeverityReview, a.BaseScore)
	}
	newScore := 5.3
	kept, err := st.KeepOwnerSeverity(ctx, "a", domain.SeverityKept{At: at.Add(100 * time.Minute), By: "key:k-3", Score: &newScore})
	if err != nil || !kept {
		t.Fatalf("keep = %v %v", kept, err)
	}
	if a := byID()["a"]; a.SeverityReview != "" || a.OwnerSeverity.Kept == nil || a.OwnerSeverity.Kept.By != "key:k-3" ||
		*a.OwnerSeverity.Kept.Score != 5.3 || !a.OwnerSeverity.Kept.At.Equal(at.Add(100*time.Minute)) || a.BaseScore != 81 {
		t.Fatalf("after keep: %+v review %q", a.OwnerSeverity, a.SeverityReview)
	}
	if kept, err := st.KeepOwnerSeverity(ctx, "n", domain.SeverityKept{At: at, By: "x"}); err != nil || kept {
		t.Fatalf("keep with none in force = %v %v", kept, err)
	}

	// Removal: the original counts again, the history stays, a second removal finds nothing.
	ended, err := st.EndOwnerSeverity(ctx, "a", "key:k-2", at.Add(2*time.Hour))
	if err != nil || !ended {
		t.Fatalf("end = %v %v", ended, err)
	}
	if again, err := st.EndOwnerSeverity(ctx, "a", "key:k-2", at.Add(3*time.Hour)); err != nil || again {
		t.Fatalf("second end = %v %v", again, err)
	}
	if a := byID()["a"]; a.BaseScore != 95 || a.OwnerSeverity != nil {
		t.Fatalf("posture a after removal = %+v", a)
	}
	if in := slaOf()["a"]; in.Bucket != domain.SLABucketCritical {
		t.Fatalf("deadline bucket of a after removal = %+v", in)
	}
	history, _ = st.OwnerSeverityHistory(ctx, "a")
	if len(history) != 2 || history[1].EndCause != "removed" || history[1].EndedBy != "key:k-2" {
		t.Fatalf("history after removal = %+v", history)
	}
	// None has no deadline bucket and counts in no severity bucket.
	none, _ := domain.NewOwnerSeverity("none", "", nil, "does not apply", who, at.Add(4*time.Hour))
	if err := st.SaveOwnerSeverities(ctx, []app.OwnerSeverityWrite{{FindingID: "b", Severity: none}}); err != nil {
		t.Fatal(err)
	}
	if in := slaOf()["b"]; in.Bucket != "" || in.CurrentBucket != "" {
		t.Fatalf("deadline bucket of b at none = %+v", in)
	}
	if b := byID()["b"]; b.BaseScore != 0 || b.OwnerSeverity == nil || b.OwnerSeverity.Level != domain.SeverityNone {
		t.Fatalf("posture b at none = %+v", b)
	}
}
