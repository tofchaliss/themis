package domain

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// cweToken finds every CWE id in a source's text. Sources spell a weakness differently: NVD
// sends one id per entry ("CWE-787", or the placeholders "NVD-CWE-noinfo" / "NVD-CWE-Other"),
// Red Hat sends a chain or a choice in one string ("CWE-120->CWE-787", "(CWE-119|CWE-20)"), and
// OSV sends a list. One rule reads all of them, so the card holds one spelling.
var cweToken = regexp.MustCompile(`(?i)\bCWE-(\d{1,5})\b`)

// NormalizeCWEs returns the distinct CWE ids found in the inputs, as "CWE-<n>", sorted by
// number. The NVD placeholders carry no id and are dropped: "no info" is not a weakness, and a
// card with none shows "not stated" (EDR-PSIRT-01).
func NormalizeCWEs(raw ...string) []string {
	seen := map[int]struct{}{}
	for _, r := range raw {
		for _, m := range cweToken.FindAllStringSubmatch(r, -1) {
			n, err := strconv.Atoi(m[1])
			if err != nil || n <= 0 {
				continue
			}
			seen[n] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	nums := make([]int, 0, len(seen))
	for n := range seen {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	out := make([]string, 0, len(nums))
	for _, n := range nums {
		out = append(out, "CWE-"+strconv.Itoa(n))
	}
	return out
}

// IssueTypeTableVersion names the CWE-to-issue-type table below. A change to the table is a
// new version and a test change, so a shown word can always be traced to the table that made it.
const IssueTypeTableVersion = "1"

// IssueTypeOther is the word for a CWE the table does not map. The CWE id is always shown
// beside the word, so nothing is hidden by it.
const IssueTypeOther = "Other"

// issueTypes is the fixed table (EDR-PSIRT-01 choice 6, owner 2026-11-23), in the order a CVE
// with several weaknesses is labelled by: the first type that any of its CWEs maps to wins.
// The order runs from what an attacker gains most to least, so a CVE that is both a memory
// safety flaw and a denial of service is labelled by the worse one.
var issueTypes = []struct {
	word string
	cwes []int
}{
	{"Code execution", []int{77, 78, 94, 95, 96, 502, 917, 1336}},
	{"Memory safety", []int{119, 120, 121, 122, 123, 124, 125, 126, 127, 131, 190, 191, 415, 416, 787, 805, 822, 823, 824, 843}},
	{"Privilege escalation", []int{250, 266, 268, 269, 270, 271, 272, 273, 274}},
	{"Authentication bypass", []int{287, 288, 290, 294, 302, 304, 306, 307, 620, 798, 1390, 1391}},
	{"Access control", []int{276, 281, 284, 285, 639, 732, 862, 863}},
	{"Injection", []int{74, 75, 88, 89, 90, 91, 93, 113, 643, 652, 943}},
	{"Path traversal", []int{22, 23, 24, 35, 36, 59, 73}},
	{"Request forgery", []int{352, 918}},
	{"Cross-site scripting", []int{79, 80, 83, 87}},
	{"Cryptographic weakness", []int{295, 296, 297, 310, 311, 312, 319, 326, 327, 328, 330, 331, 338, 347}},
	{"Information disclosure", []int{200, 201, 203, 208, 209, 212, 359, 532, 538}},
	{"Race condition", []int{362, 364, 366, 367}},
	{"Denial of service", []int{399, 400, 401, 404, 407, 459, 476, 617, 662, 667, 674, 770, 772, 789, 834, 835, 1050, 1333}},
	{"Input validation", []int{20, 1284, 1286, 1287}},
}

var issueTypeRank = func() map[int]int {
	m := map[int]int{}
	for i, t := range issueTypes {
		for _, c := range t.cwes {
			m[c] = i
		}
	}
	return m
}()

// IssueType labels a CVE by its weaknesses with one short word from the fixed table. No CWE
// at all returns "" (the GUI shows "not stated"); CWEs the table does not map return
// IssueTypeOther. It is a display label: nothing decides on it.
func IssueType(cwes []string) string {
	best := -1
	for _, c := range cwes {
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CWE-"))
		if err != nil {
			continue
		}
		if r, ok := issueTypeRank[n]; ok && (best < 0 || r < best) {
			best = r
		}
	}
	switch {
	case best >= 0:
		return issueTypes[best].word
	case len(cwes) > 0:
		return IssueTypeOther
	default:
		return ""
	}
}
