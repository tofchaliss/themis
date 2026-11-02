package domain_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// One announcement per release (EDR-INCIDENT-01 D1): the counts are over every distinct CVE and
// package, the carried list is deterministic and capped, and the cap never touches the counts.
func TestNewFixAvailable(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	items := []domain.FixAvailableItem{
		{FindingID: "f-2", CVE: "CVE-2026-2", Package: "kernel", Ecosystem: "rpm", Fixes: []string{"0:4.18.0-553.80.1.el8_10"}, Advisories: []string{"RHSA-2026:2"}},
		{FindingID: "f-1", CVE: "CVE-2026-1", Package: "openssl", Ecosystem: "rpm", Fixes: []string{"1:1.1.1k-14.el8_6"}},
		{FindingID: "f-1", CVE: "CVE-2026-1", Package: "kernel", Ecosystem: "rpm", Fixes: []string{"0:4.18.0-553.80.1.el8_10"}},
	}
	ev := domain.NewFixAvailable("rel-1", items, at)
	if ev.ReleaseID != "rel-1" || ev.CVECount != 2 || ev.PackageCount != 2 || len(ev.Items) != 3 || !ev.OccurredAt.Equal(at) {
		t.Fatalf("event = %+v, want 2 CVEs, 2 packages, 3 items", ev)
	}
	if ev.Items[0].CVE != "CVE-2026-1" || ev.Items[0].Package != "kernel" || ev.Items[1].Package != "openssl" || ev.Items[2].CVE != "CVE-2026-2" {
		t.Errorf("items not sorted by CVE then package: %+v", ev.Items)
	}
	if items[0].CVE != "CVE-2026-2" {
		t.Error("the caller's slice must not be reordered")
	}

	var many []domain.FixAvailableItem
	for i := 0; i < domain.FixAvailableItemLimit+7; i++ {
		many = append(many, domain.FixAvailableItem{CVE: fmt.Sprintf("CVE-2026-%04d", i), Package: "kernel", Fixes: []string{"x"}})
	}
	capped := domain.NewFixAvailable("rel-2", many, at)
	if len(capped.Items) != domain.FixAvailableItemLimit || capped.CVECount != domain.FixAvailableItemLimit+7 || capped.PackageCount != 1 {
		t.Errorf("capped = %d items, %d CVEs, %d packages; want the cap, the full CVE count, 1 package",
			len(capped.Items), capped.CVECount, capped.PackageCount)
	}
}
