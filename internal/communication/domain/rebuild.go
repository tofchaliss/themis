package domain

import (
	"sort"
	"strings"
	"time"
)

// The rebuild loop's comparison rules (EDR-DELIVERY-01 M2-5 / N-M2e), pure and deterministic:
// which SBOM a rebuild is compared against, which Findings a cycle set out to close, and
// whether it closed them. Nothing here reads anything — the worker (N-M2f/N-M2i) feeds it the
// Evidence listing and the Governance posture and acts on the answer.

// The severity-bucket floors over Governance's `base_score` (EDR-DELIVERY-01 M1b-5 / M2-2),
// RESTATED here rather than imported: contexts share wire vocabulary, not packages. They are
// floors, not ranges — a score belongs to the highest bucket whose floor it reaches.
const (
	SeverityCriticalFloor = 90
	SeverityHighFloor     = 70
	SeverityMediumFloor   = 40
)

// SBOMRecord is one SBOM filed against a Release, as Evidence lists it: its id and when it
// was filed. Upload order is the ONLY order the baseline rule knows (M2-5).
type SBOMRecord struct {
	ID      string
	FiledAt time.Time
}

// SelectPreviousSBOM picks the baseline for a comparison: the SBOM filed immediately before
// newID on the same Release, by upload order. Ties on FiledAt are broken by id, so the answer
// is the same whatever order the listing arrived in. There is no baseline when newID is the
// first SBOM of the Release — or is not in the listing at all, which the caller treats the
// same way: a comparison without a known previous side has nothing to say (M2-5: no window,
// no "baseline of record", no knob).
func SelectPreviousSBOM(records []SBOMRecord, newID string) (SBOMRecord, bool) {
	ordered := make([]SBOMRecord, 0, len(records))
	for _, r := range records {
		if strings.TrimSpace(r.ID) != "" {
			ordered = append(ordered, r)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].FiledAt.Equal(ordered[j].FiledAt) {
			return ordered[i].FiledAt.Before(ordered[j].FiledAt)
		}
		return ordered[i].ID < ordered[j].ID
	})
	for i, r := range ordered {
		if r.ID == newID {
			if i == 0 {
				return SBOMRecord{}, false
			}
			return ordered[i-1], true
		}
	}
	return SBOMRecord{}, false
}

// PostureRow is the slice of a Release's posture the loop reasons over: one open Finding's
// CVE and its base score. It mirrors Governance's posture read, by CVE, the same key D16's
// release comparison diffs on.
type PostureRow struct {
	CVE       string
	BaseScore int
}

// TargetedSet is what a rebuild cycle set out to close: the Critical and High Findings present
// AT CYCLE START, keyed by CVE. It is captured once and never grows (M2-5): a Critical that
// appears mid-cycle shows in the ticket's counts but waits for the next cycle, because a
// growing target can never be reached and would spend the attempt budget on work the cycle
// did not set out to do.
type TargetedSet struct {
	cves []string
}

// NewTargetedSet captures the Critical+High CVEs of a posture, deduplicated and sorted.
// Rows without a CVE cannot be tracked by CVE and are left out.
func NewTargetedSet(start []PostureRow) TargetedSet {
	seen := map[string]bool{}
	var cves []string
	for _, row := range start {
		cve := strings.TrimSpace(row.CVE)
		if cve == "" || row.BaseScore < SeverityHighFloor || seen[cve] {
			continue
		}
		seen[cve] = true
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	return TargetedSet{cves: cves}
}

// TargetedSetOf rebuilds a set from its recorded CVEs (a cycle row), trimmed, deduplicated and
// sorted — the same shape NewTargetedSet produces, so a persisted set compares identically.
func TargetedSetOf(cves []string) TargetedSet {
	seen := map[string]bool{}
	var out []string
	for _, cve := range cves {
		cve = strings.TrimSpace(cve)
		if cve == "" || seen[cve] {
			continue
		}
		seen[cve] = true
		out = append(out, cve)
	}
	sort.Strings(out)
	return TargetedSet{cves: out}
}

// CVEs returns the targeted CVEs in sorted order (a copy).
func (t TargetedSet) CVEs() []string { return append([]string(nil), t.cves...) }

// Len is the number of targeted CVEs.
func (t TargetedSet) Len() int { return len(t.cves) }

// Closure is the outcome of comparing the targeted set against the posture AFTER a rebuild
// was evaluated: which targeted CVEs no longer open a Finding (Closed) and which still do
// (Open). Complete is the loop's SUCCESS stop condition (M2-8): nothing targeted is still
// open. Findings the comparison finds that were never targeted appear in neither list.
type Closure struct {
	Closed   []string
	Open     []string
	Complete bool
}

// Closure compares the targeted set against the current posture. A targeted CVE is closed
// when it opens no Finding on the Release now — D16's "fixed" rule — regardless of score, so
// a CVE whose severity dropped is still open: a milder flaw is not a closed one. The set does
// not change: whatever else `current` carries is reported by the ticket, not by this.
func (t TargetedSet) Closure(current []PostureRow) Closure {
	still := map[string]bool{}
	for _, row := range current {
		still[strings.TrimSpace(row.CVE)] = true
	}
	out := Closure{Closed: []string{}, Open: []string{}}
	for _, cve := range t.cves {
		if still[cve] {
			out.Open = append(out.Open, cve)
		} else {
			out.Closed = append(out.Closed, cve)
		}
	}
	out.Complete = len(out.Open) == 0
	return out
}
