package domain

import "strings"

// RepairSplitRanges re-pairs a range list the pre-2026-10-14 OSV reader wrote: that reader
// rendered OSV's ordered event list one event at a time, so `{introduced: 0}, {fixed: 1.4.3}`
// came out as two consecutive rules, `>=0` then `<1.4.3`. A proposal keeps its ranges in the
// order they were rendered, so the pairing is recoverable from the list alone: a lone lower
// bound immediately followed by a lone upper bound is one interval. Anything already paired,
// a lower bound not followed by an upper one (genuinely open-ended), or an upper bound on its
// own passes through unchanged. The second result says whether anything changed, so a caller
// folds a corrected statement only where there is something to correct.
func RepairSplitRanges(ranges []string) ([]string, bool) {
	out := make([]string, 0, len(ranges))
	changed := false
	for i := 0; i < len(ranges); i++ {
		r := strings.TrimSpace(ranges[i])
		if isLoneLower(r) && i+1 < len(ranges) && isLoneUpper(strings.TrimSpace(ranges[i+1])) {
			out = append(out, r+","+strings.TrimSpace(ranges[i+1]))
			changed = true
			i++
			continue
		}
		out = append(out, r)
	}
	return out, changed
}

func isLoneLower(r string) bool {
	return strings.HasPrefix(r, ">=") && !strings.Contains(r, ",")
}

func isLoneUpper(r string) bool {
	return (strings.HasPrefix(r, "<")) && !strings.Contains(r, ",")
}
