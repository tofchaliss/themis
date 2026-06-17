package domain

import (
	"regexp"
	"strings"
)

var cveCanonicalRE = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

// NormalizeCVEID returns canonical CVE-* form when id uses a known OSV distro prefix
// (e.g. ALPINE-CVE-2024-1234 → CVE-2024-1234). Non-CVE identifiers are returned unchanged.
func NormalizeCVEID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return id
	}
	upper := strings.ToUpper(id)
	if cveCanonicalRE.MatchString(upper) {
		return upper
	}
	if idx := strings.Index(upper, "CVE-"); idx > 0 {
		candidate := upper[idx:]
		if cveCanonicalRE.MatchString(candidate) {
			return candidate
		}
	}
	return id
}
