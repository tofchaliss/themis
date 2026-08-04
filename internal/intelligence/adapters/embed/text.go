package embed

import "strings"

// SubjectText composes the text embedded for a Finding — used identically at population time
// (indexing a past decision) and at query time (retrieving precedent), so the two vectors are
// comparable. It intentionally omits the CVE id (a unique token with no cross-CVE signal) and
// leans on the component purls + severity that carry semantic similarity across DIFFERENT CVEs
// (Δ3a RC-1, Book IV Ch 8). The exact composition is the R5 "what to embed" A/B — kept here in
// ONE place so a change moves the index and the query together.
func SubjectText(severity string, components []string) string {
	parts := make([]string, 0, len(components)+1)
	parts = append(parts, components...)
	if severity != "" {
		parts = append(parts, severity)
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}
