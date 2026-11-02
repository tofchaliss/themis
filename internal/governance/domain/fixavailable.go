package domain

import (
	"sort"
	"time"
)

// The fix-available fact (EDR-INCIDENT-01 D1). Knowledge announces, per occurrence, that a
// vendor fix is newly on record for a package a release has OPEN; Governance gathers those
// notices and tells a person ONCE PER RELEASE — during a wave one advisory fixes many CVEs in
// one build, and a message per CVE is the noise the owner described. It is a fact, not a
// transition: no Finding, Position or proposal changes because of it. "Fix available" is the
// vendor's statement; "patched" is proven only by new evidence for the release (D5).

// FixAvailableItemLimit caps the items one announcement carries; the counts stay complete.
const FixAvailableItemLimit = 100

// FixAvailableItem is one (Finding, package) with the bounds now on record that the release's
// install is below, and the advisories that shipped them when the vendor statements say.
type FixAvailableItem struct {
	FindingID  FindingID
	CVE        string
	Package    string
	Ecosystem  string
	Fixes      []string
	Advisories []string `json:"Advisories,omitempty"`
}

// FixAvailable is governance.fix_available.v1: one release, the CVEs and packages a vendor fix
// is now on record for, and the items behind the counts (capped).
type FixAvailable struct {
	ReleaseID    string
	CVECount     int
	PackageCount int
	Items        []FixAvailableItem
	OccurredAt   time.Time
}

// NewFixAvailable builds the announcement for one release from its items: items are sorted by
// CVE then package (deterministic wire), the counts are over the distinct CVEs and packages of
// ALL items, and the carried list is capped at FixAvailableItemLimit.
func NewFixAvailable(releaseID string, items []FixAvailableItem, at time.Time) FixAvailable {
	sorted := append([]FixAvailableItem(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CVE != sorted[j].CVE {
			return sorted[i].CVE < sorted[j].CVE
		}
		return sorted[i].Package < sorted[j].Package
	})
	cves, pkgs := map[string]struct{}{}, map[string]struct{}{}
	for _, it := range sorted {
		cves[it.CVE] = struct{}{}
		pkgs[it.Package] = struct{}{}
	}
	if len(sorted) > FixAvailableItemLimit {
		sorted = sorted[:FixAvailableItemLimit]
	}
	return FixAvailable{
		ReleaseID: releaseID, CVECount: len(cves), PackageCount: len(pkgs),
		Items: sorted, OccurredAt: at,
	}
}
