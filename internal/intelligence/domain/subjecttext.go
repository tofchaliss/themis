package domain

import "strings"

// SubjectText composes the text embedded for a Finding — used identically at population time
// (indexing a past decision) and at query time (retrieving precedent), so the two vectors are
// comparable. It intentionally omits the CVE id (a unique token with no cross-CVE signal) and
// leans on the component purls + severity that carry semantic similarity across DIFFERENT CVEs
// (Δ3a RC-1, Book IV Ch 8). The exact composition is the R5 "what to embed" A/B — kept in ONE
// place so a change moves the index and the query together.
//
// It lives in the domain ring rather than beside the embedders because it is a RULE, not an
// adapter concern: it defines what a Finding looks like to the semantic index, and the index
// writer (the population consumer, an adapter) and the index reader (the precedent use case,
// in app) must both apply it. A pure I/O-free rule that two rings share belongs in the ring
// they can both import. Nothing here embeds anything — turning text into a vector is the
// Embedder port's job, and it stays in adapters.
//
// Measured (R5, 2026-08-05): this composition scored recall@1 = 1.00 / MRR = 1.00. Adding the
// CVE id was neutral; adding the description HURT (0.83) — a longer text is not a better
// embedding when the discriminating signal is the component set.
func SubjectText(severity string, components []string) string {
	parts := make([]string, 0, len(components)+1)
	parts = append(parts, components...)
	if severity != "" {
		parts = append(parts, severity)
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}
