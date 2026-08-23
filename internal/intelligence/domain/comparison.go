package domain

// ReleaseComparison is the cross-release posture diff, received VERBATIM from Governance's
// comparison read (EDR-GOVERNANCE-01 D16) — the deterministic core compare_releases@v1
// narrates (AI-CMP-1). The buckets arrive server-sorted (residual then effective priority,
// descending) and the runtime never re-derives them: what the fix achieved is a query result,
// not a model opinion.
type ReleaseComparison struct {
	BaselineID  string
	CandidateID string
	// Fixed rows carry the BASELINE's state (a fix closes the question forward, it never
	// rewrites history); New and Persisting carry the CANDIDATE's.
	Fixed      []PostureEntry
	New        []PostureEntry
	Persisting []PostureEntry
}

// Empty reports whether there is nothing to narrate at all — both postures were empty. The
// gateway answers that deterministically, without spending a model call.
func (c ReleaseComparison) Empty() bool {
	return len(c.Fixed) == 0 && len(c.New) == 0 && len(c.Persisting) == 0
}

// Grounds reports whether ref names something this comparison actually contained — the two
// release ids or any bucket row's identifiers. Grounding Verification anchors here for
// compare_releases (T8): a citation naming a CVE in neither posture is a hallucination
// regardless of how plausible the prose reads.
func (c ReleaseComparison) Grounds(ref string) bool {
	if ref == "" {
		return false
	}
	if ref == c.BaselineID || ref == c.CandidateID {
		return true
	}
	for _, bucket := range [][]PostureEntry{c.Fixed, c.New, c.Persisting} {
		for _, e := range bucket {
			if e.grounds(ref) {
				return true
			}
		}
	}
	return false
}

// maxComparisonRows caps each bucket as SHOWN to the model. The buckets arrive worst-first, so
// the cap keeps the most important rows; the Omitted counts keep the truncation honest — a
// prompt that silently dropped rows would let the model claim completeness it was never given.
const maxComparisonRows = 15

// FixedShown / NewShown / PersistingShown are the prompt's views of each bucket, capped at
// maxComparisonRows (worst-first, as the read sorted them).
func (c ReleaseComparison) FixedShown() []PostureEntry      { return capEntries(c.Fixed) }
func (c ReleaseComparison) NewShown() []PostureEntry        { return capEntries(c.New) }
func (c ReleaseComparison) PersistingShown() []PostureEntry { return capEntries(c.Persisting) }

// FixedOmitted / NewOmitted / PersistingOmitted count the rows the cap hid from the prompt.
func (c ReleaseComparison) FixedOmitted() int      { return omitted(c.Fixed) }
func (c ReleaseComparison) NewOmitted() int        { return omitted(c.New) }
func (c ReleaseComparison) PersistingOmitted() int { return omitted(c.Persisting) }

func capEntries(in []PostureEntry) []PostureEntry {
	if len(in) > maxComparisonRows {
		return in[:maxComparisonRows]
	}
	return in
}

func omitted(in []PostureEntry) int {
	if n := len(in) - maxComparisonRows; n > 0 {
		return n
	}
	return 0
}
