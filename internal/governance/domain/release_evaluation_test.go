package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

func TestValidDiscoveryCause(t *testing.T) {
	for _, ok := range []string{domain.CauseNewSBOM, domain.CauseRediscovery} {
		if !domain.ValidDiscoveryCause(ok) {
			t.Errorf("%q must be a valid cause", ok)
		}
	}
	for _, bad := range []string{"", "new-sbom", "NEW_SBOM", "other", "rebuild"} {
		if domain.ValidDiscoveryCause(bad) {
			t.Errorf("%q must be refused — the enum is closed", bad)
		}
	}
}

// The M1b-5 ladder at its EDGES, which is where an off-by-one lives: the floor of each bucket
// belongs to that bucket, and 0 belongs to none.
func TestCountSeverityBuckets_LadderEdges(t *testing.T) {
	got := domain.CountSeverityBuckets([]int{90, 70, 40, 1, 0})
	want := domain.SeverityCounts{Critical: 1, High: 1, Medium: 1, Low: 1}
	if got != want {
		t.Errorf("counts = %+v, want %+v (0 is Unknown and counted nowhere)", got, want)
	}

	for _, tc := range []struct {
		score int
		want  domain.SeverityCounts
	}{
		{100, domain.SeverityCounts{Critical: 1}},
		{90, domain.SeverityCounts{Critical: 1}},
		{89, domain.SeverityCounts{High: 1}},
		{70, domain.SeverityCounts{High: 1}},
		{69, domain.SeverityCounts{Medium: 1}},
		{40, domain.SeverityCounts{Medium: 1}},
		{39, domain.SeverityCounts{Low: 1}},
		{1, domain.SeverityCounts{Low: 1}},
		{0, domain.SeverityCounts{}},
		{-5, domain.SeverityCounts{}},
	} {
		if got := domain.CountSeverityBuckets([]int{tc.score}); got != tc.want {
			t.Errorf("score %d → %+v, want %+v", tc.score, got, tc.want)
		}
	}
}

func TestCountSeverityBuckets_NoFindingsIsAllZero(t *testing.T) {
	if got := (domain.CountSeverityBuckets(nil)); got != (domain.SeverityCounts{}) {
		t.Errorf("no Findings → %+v, want all zero (the success case, not a skip)", got)
	}
}

func TestNewReleaseEvaluated(t *testing.T) {
	counts := domain.SeverityCounts{Critical: 2, High: 3, Medium: 4, Low: 5}
	ev := domain.NewReleaseEvaluated("prod-1", "prj-1", "rel-1", "ev-1", domain.CauseRediscovery, counts)
	if ev.ProductID != "prod-1" || ev.ProjectID != "prj-1" || ev.ReleaseID != "rel-1" ||
		ev.SBOMID != "ev-1" || ev.Cause != "rediscovery" || ev.SeverityCounts != counts {
		t.Errorf("event = %+v", ev)
	}
}
