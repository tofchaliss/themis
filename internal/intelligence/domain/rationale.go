package domain

import (
	"regexp"
	"sort"
	"strings"
)

// maxRationaleWarnings caps how many ungrounded mentions are reported. A model that has gone
// badly off the rails can name dozens; a human needs to know the rationale is unreliable, not
// read the whole list, and an unbounded slice would be a denial-of-service on the log line.
const maxRationaleWarnings = 5

// Identifier shapes worth checking. Each is a token a reader would reasonably treat as a
// verifiable fact — an id they could look up — rather than as prose. Ordinary words, version
// numbers and package names are deliberately NOT matched: the goal is to flag false precision,
// not to grade the writing.
var rationaleIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`), // UUID
	regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`),                                                            // CVE id
	regexp.MustCompile(`\bpkg:[A-Za-z0-9._-]+/[A-Za-z0-9._@%/-]+`),                                        // PURL
}

// UngroundedMentions returns the identifier-shaped tokens in free text that the authoritative
// grounding does NOT contain (EDR-TRUST-01 T8 / backlog TRUST-8).
//
// Why this exists. Grounding Verification checks the STRUCTURED `evidence[].ref` array by set
// membership, and correctly ignores the free-text rationale — prose cannot be set-membership
// checked, and no honest validator can decide whether an English sentence is true. But the
// rationale is what a human reads when exercising the decision T4 reserves for them, so the
// most persuasive part of an AI proposal carries the weakest guarantee.
//
// Observed on a live model (2026-08-06): a proposal for CVE-2026-41842 cited faultline
// `a38d9c32…` correctly in both evidence refs and passed every validation stage, while its
// reasoning stated the component was "included in the release ee006ff7-…" — an unrelated
// release from a prior day that the model was never given. Two correct refs and one confident,
// specific, wrong id, indistinguishable to a reviewer.
//
// What this is NOT. It does not verify the rationale, score it, or reject the proposal. It
// answers exactly one deterministic question — "does this text name an identifier nobody gave
// the model?" — which is cheap, needs no model, and cannot itself hallucinate. A clean result
// is NOT a guarantee the narrative is true; it only means the narrative invented no ids. That
// asymmetry is the honest limit of the check, and why it produces a warning rather than a
// verdict.
//
// Results are deduplicated, sorted (so the same output is reported identically every time —
// telemetry that varies run to run is unreadable), and capped.
func UngroundedMentions(text string, ac AssembledContext) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	for _, re := range rationaleIDPatterns {
		for _, m := range re.FindAllString(text, -1) {
			// Trailing punctuation clings to a PURL match ("…@1.2.3." at the end of a sentence)
			// and would make a grounded ref look ungrounded.
			tok := strings.TrimRight(m, ".,;:)]}\"'")
			if tok == "" || ac.Grounds(tok) {
				continue
			}
			seen[tok] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for tok := range seen {
		out = append(out, tok)
	}
	sort.Strings(out)
	if len(out) > maxRationaleWarnings {
		out = out[:maxRationaleWarnings]
	}
	return out
}
