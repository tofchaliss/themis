package domain_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

// M2-5: the baseline is the SBOM filed immediately before the new one on the same Release, by
// upload order — whatever order the listing arrived in, with ties broken by id, and NO
// baseline when the new SBOM is the first (or unknown).
func TestSelectPreviousSBOM_ByUploadOrder(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	records := []domain.SBOMRecord{
		{ID: "ev-3", FiledAt: t0.Add(2 * time.Hour)},
		{ID: "ev-1", FiledAt: t0},
		{ID: "", FiledAt: t0.Add(90 * time.Minute)}, // a nameless row cannot be a baseline
		{ID: "ev-2", FiledAt: t0.Add(time.Hour)},
		{ID: "ev-4", FiledAt: t0.Add(3 * time.Hour)},
	}
	for _, tc := range []struct {
		newID string
		want  string
		ok    bool
	}{
		{"ev-4", "ev-3", true},
		{"ev-3", "ev-2", true},
		{"ev-2", "ev-1", true},
		{"ev-1", "", false},  // the first SBOM has no previous one
		{"ev-99", "", false}, // unknown to the listing: nothing to compare against
		{"", "", false},      // an unnamed new SBOM is not matched against the dropped row
	} {
		got, ok := domain.SelectPreviousSBOM(records, tc.newID)
		if ok != tc.ok || got.ID != tc.want {
			t.Errorf("previous of %q = %q/%v, want %q/%v", tc.newID, got.ID, ok, tc.want, tc.ok)
		}
	}
	// Same instant: the id decides, so a listing in any order gives one answer.
	tie := []domain.SBOMRecord{{ID: "ev-b", FiledAt: t0}, {ID: "ev-a", FiledAt: t0}, {ID: "ev-c", FiledAt: t0.Add(time.Minute)}}
	if got, ok := domain.SelectPreviousSBOM(tie, "ev-c"); !ok || got.ID != "ev-b" {
		t.Errorf("tie-break: previous of ev-c = %q/%v, want ev-b", got.ID, ok)
	}
	if got, ok := domain.SelectPreviousSBOM(tie, "ev-b"); !ok || got.ID != "ev-a" {
		t.Errorf("tie-break: previous of ev-b = %q/%v, want ev-a", got.ID, ok)
	}
	if _, ok := domain.SelectPreviousSBOM(nil, "ev-1"); ok {
		t.Error("an empty listing has no baseline")
	}
}

// M2-5: the targeted set is Critical+High at cycle start and does not grow. A Critical that
// appears mid-loop is neither closed nor open for this cycle; a targeted CVE that still opens a
// Finding is open whatever its score became; closure is complete only when nothing targeted
// remains.
func TestTargetedSetClosure_DoesNotGrowMidLoop(t *testing.T) {
	start := []domain.PostureRow{
		{CVE: "CVE-2026-3", BaseScore: 95},
		{CVE: "CVE-2026-1", BaseScore: 70}, // exactly the High floor
		{CVE: "CVE-2026-2", BaseScore: 69}, // Medium: counted in the ticket, never targeted
		{CVE: "CVE-2026-1", BaseScore: 90}, // the same CVE twice (two Findings) is one target
		{CVE: "", BaseScore: 99},           // untrackable by CVE
		{CVE: " CVE-2026-4 ", BaseScore: 80},
	}
	set := domain.NewTargetedSet(start)
	if got, want := set.CVEs(), []string{"CVE-2026-1", "CVE-2026-3", "CVE-2026-4"}; !reflect.DeepEqual(got, want) || set.Len() != 3 {
		t.Fatalf("targeted = %v (len %d), want %v", got, set.Len(), want)
	}
	set.CVEs()[0] = "mutated" // the accessor hands out a copy
	if set.CVEs()[0] != "CVE-2026-1" {
		t.Error("CVEs() must not expose the set's own slice")
	}

	// After the first rebuild: CVE-2026-3 is gone, CVE-2026-1 persists at a lower score, a
	// NEW Critical appeared, and CVE-2026-4 persists.
	after1 := []domain.PostureRow{
		{CVE: "CVE-2026-1", BaseScore: 55},
		{CVE: "CVE-2026-5", BaseScore: 98}, // new mid-loop: reported, not targeted
		{CVE: "CVE-2026-4", BaseScore: 80},
		{CVE: "CVE-2026-2", BaseScore: 69},
	}
	c := set.Closure(after1)
	if !reflect.DeepEqual(c.Closed, []string{"CVE-2026-3"}) || !reflect.DeepEqual(c.Open, []string{"CVE-2026-1", "CVE-2026-4"}) || c.Complete {
		t.Errorf("closure after rebuild 1 = %+v", c)
	}
	if set.Len() != 3 {
		t.Errorf("the set grew to %d mid-loop", set.Len())
	}

	// After the second rebuild everything targeted is gone; the new Critical is still there and
	// still not this cycle's business.
	after2 := []domain.PostureRow{{CVE: "CVE-2026-5", BaseScore: 98}}
	c = set.Closure(after2)
	if !reflect.DeepEqual(c.Closed, []string{"CVE-2026-1", "CVE-2026-3", "CVE-2026-4"}) || len(c.Open) != 0 || !c.Complete {
		t.Errorf("closure after rebuild 2 = %+v, want complete", c)
	}

	// An empty target is trivially complete, and both lists are non-nil so a consumer can
	// range and encode them without a nil check.
	if c = domain.NewTargetedSet(nil).Closure(after1); !c.Complete || c.Closed == nil || c.Open == nil {
		t.Errorf("empty target closure = %+v", c)
	}
}
