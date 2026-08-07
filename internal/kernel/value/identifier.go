package value

import (
	"regexp"
	"strings"
)

// identifierPatterns match the token shapes that identify something in this system: an opaque
// UUID, a CVE id, and a package URL. Ordinary words, version numbers and bare package names are
// deliberately excluded — these are the tokens a reader would treat as a verifiable reference,
// not as prose.
var identifierPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
	regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`),
	regexp.MustCompile(`\bpkg:[A-Za-z0-9._-]+/[A-Za-z0-9._@%/-]+`),
}

// IdentifierTokens extracts the identifier-shaped tokens from free text, in order of
// appearance and deduplicated.
//
// It exists because a model asked to cite a reference frequently LABELS it — emitting
// `faultline b1be6f86-…` where the grounding set holds `b1be6f86-…`. Verified on a live model
// 2026-08-07: a recommendation cited the correct faultline id, prefixed with the word
// "faultline", and was refused as ungrounded. The answer was right; only the formatting was not.
//
// Extraction is the honest way to tolerate that WITHOUT weakening verification. Substring
// matching would be the tempting alternative and is unsafe — "CVE-2024-1000" is a substring of
// "CVE-2024-10000", so a grounded id would vouch for a different one. Pulling out whole,
// anchored identifier tokens and then requiring
// an EXACT set-membership match on each keeps the guarantee intact: the caller still proves the
// id was supplied, it merely stops being confused by a human-readable label around it.
func IdentifierTokens(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, re := range identifierPatterns {
		for _, m := range re.FindAllString(text, -1) {
			// Trailing sentence punctuation clings to a PURL match and would make a supplied
			// identifier look unsupplied.
			// Every pattern is anchored on non-trimmable characters, so a match can never trim
			// away to nothing — no empty-token guard is needed.
			tok := strings.TrimRight(m, ".,;:)]}\"'")
			if _, dup := seen[tok]; dup {
				continue
			}
			seen[tok] = struct{}{}
			out = append(out, tok)
		}
	}
	return out
}
