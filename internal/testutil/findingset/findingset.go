// Package findingset is the CR-10 finding-set regression harness. It normalizes a
// set of correlated findings into stable keys and diffs two sets, so any change to
// the correlation core (version engine, sources, merge) is reviewed as an explicit
// added/removed delta against a committed golden snapshot rather than slipping in
// silently. Set UPDATE_GOLDEN=1 to regenerate a golden file.
package findingset

import (
	"os"
	"sort"
	"strings"
)

// KeyString is the canonical identity of a finding for diffing: the
// version-qualified component purl, the CVE, and the source that produced it.
func KeyString(componentPURL, cveID, source string) string {
	return componentPURL + "|" + cveID + "|" + source
}

// Snapshot returns a deduplicated, sorted copy of keys — the stable form used for
// golden comparison.
func Snapshot(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Diff reports keys present in after but not before (added) and in before but not
// after (removed). Both inputs are snapshotted first, so order/duplicates are
// irrelevant.
func Diff(before, after []string) (added, removed []string) {
	beforeSet := make(map[string]struct{}, len(before))
	for _, k := range Snapshot(before) {
		beforeSet[k] = struct{}{}
	}
	afterSet := make(map[string]struct{}, len(after))
	for _, k := range Snapshot(after) {
		afterSet[k] = struct{}{}
	}
	for k := range afterSet {
		if _, ok := beforeSet[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range beforeSet {
		if _, ok := afterSet[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// T is the minimal testing surface AssertGolden needs (avoids importing testing).
type T interface {
	Helper()
	Fatalf(format string, args ...any)
}

// AssertGolden compares got against the golden file at path, failing with the
// explicit finding-set delta on drift. When UPDATE_GOLDEN=1 it (re)writes the
// golden file instead of comparing.
func AssertGolden(t T, path string, got []string) {
	t.Helper()
	snapshot := Snapshot(got)
	content := strings.Join(snapshot, "\n")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with UPDATE_GOLDEN=1 to create)", path, err)
	}
	want := splitNonEmpty(string(raw))
	added, removed := Diff(want, snapshot)
	if len(added) > 0 || len(removed) > 0 {
		t.Fatalf("finding-set drift vs %s:\n  added:   %v\n  removed: %v\n(run with UPDATE_GOLDEN=1 to accept)", path, added, removed)
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
