package domain

import (
	"sort"
	"time"
)

// The upload outcome (EDR-REMEDIATION-01 D3): what one new SBOM changed on a Release, in four
// buckets, against the immediately-previous SBOM of the same Release (the N-M2e baseline rule).
//
// It is a REPORT, never a state (R-B). `no_longer_present` closes nothing and `reappeared`
// re-opens nothing; a Finding keeps its stage and its Position whatever bucket it lands in.
// Presence is read from the SBOMs' inventories by purl — the same purl Knowledge matched — so a
// Finding none of whose components appears in either SBOM (one opened from a scanner report, or
// from an older SBOM) is in no bucket: the two SBOMs say nothing about it, and it is counted as
// `not_judged` so the totals still add up.

// UploadFinding is one Finding as the classifier reads it.
type UploadFinding struct {
	CVE       string
	Stage     Stage
	CreatedAt time.Time
	// PURLs are the Finding's ACTIVE (non-retired) component purls.
	PURLs []string
}

// UploadBaseline is the previous SBOM, when there is one.
type UploadBaseline struct {
	PURLs   map[string]bool
	FiledAt time.Time
}

// UploadOutcomeCVELimit caps each bucket's CVE list; the counts are always complete.
const UploadOutcomeCVELimit = 50

// UploadOutcome is the four buckets: counts, and the CVEs in each (sorted, capped).
type UploadOutcome struct {
	New             int      `json:"new"`
	Reappeared      int      `json:"reappeared"`
	NoLongerPresent int      `json:"no_longer_present"`
	Unchanged       int      `json:"unchanged"`
	NotJudged       int      `json:"not_judged"`
	NewCVEs         []string `json:"new_cves,omitempty"`
	ReappearedCVEs  []string `json:"reappeared_cves,omitempty"`
	GoneCVEs        []string `json:"no_longer_present_cves,omitempty"`
	// HasBaseline is false on a Release's first SBOM: everything present is `new`.
	HasBaseline bool `json:"has_baseline"`
}

func anyIn(purls []string, set map[string]bool) bool {
	for _, p := range purls {
		if set[p] {
			return true
		}
	}
	return false
}

func stageOpen(s Stage) bool { return s != StageResolved && s != StageArchived }

// ClassifyUpload buckets a Release's Findings for one new SBOM. prev is nil on the first SBOM.
func ClassifyUpload(findings []UploadFinding, current map[string]bool, prev *UploadBaseline) UploadOutcome {
	out := UploadOutcome{HasBaseline: prev != nil}
	var newC, reC, goneC []string
	for _, f := range findings {
		inCur := anyIn(f.PURLs, current)
		inPrev := prev != nil && anyIn(f.PURLs, prev.PURLs)
		switch {
		case inCur && !inPrev:
			// Present now, absent before. A Finding created after the baseline was filed did
			// not exist before this SBOM; an older one has come back.
			if prev == nil || f.CreatedAt.After(prev.FiledAt) {
				out.New++
				newC = append(newC, f.CVE)
			} else {
				out.Reappeared++
				reC = append(reC, f.CVE)
			}
		case inCur && inPrev && stageOpen(f.Stage):
			out.Unchanged++
		case !inCur && inPrev && stageOpen(f.Stage):
			out.NoLongerPresent++
			goneC = append(goneC, f.CVE)
		default:
			out.NotJudged++
		}
	}
	out.NewCVEs, out.ReappearedCVEs, out.GoneCVEs = capped(newC), capped(reC), capped(goneC)
	return out
}

func capped(cves []string) []string {
	sort.Strings(cves)
	if len(cves) > UploadOutcomeCVELimit {
		return cves[:UploadOutcomeCVELimit]
	}
	return cves
}
