package domain

import (
	"sort"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
)

// maxRationaleWarnings caps how many ungrounded mentions are reported. A model that has gone
// badly off the rails can name dozens; a human needs to know the rationale is unreliable, not
// read the whole list, and an unbounded slice would be a denial-of-service on the log line.
const maxRationaleWarnings = 5

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
	var out []string
	for _, tok := range value.IdentifierTokens(text) {
		if !ac.Grounds(tok) {
			out = append(out, tok)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	if len(out) > maxRationaleWarnings {
		out = out[:maxRationaleWarnings]
	}
	return out
}
