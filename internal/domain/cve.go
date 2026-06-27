package domain

import (
	"regexp"
	"strings"
)

// CVSSData is a CVE's CVSS verdict, used by the CR-5 NVD-by-CVE backfill to fill
// severity/score/vector for catalog rows that came from feeds without CVSS
// (apk/rpm OSV findings).
type CVSSData struct {
	Severity string
	Score    float64
	Vector   string
}

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

// NormalizeSeverity canonicalises a feed-supplied severity for the vulnerability
// catalog: surrounding whitespace is trimmed and a blank value maps to "unknown".
// Without this the catalog stores an empty string for feed records that carry no
// severity (e.g. an Alpine OSV entry with no database_specific.severity), and
// COALESCE(v.severity, 'unknown') cannot fold "" — it only replaces SQL NULL — so
// those findings surface as a stray empty "" bucket in GET /api/v1/status.
func NormalizeSeverity(s string) string {
	if trimmed := strings.TrimSpace(s); trimmed != "" {
		return trimmed
	}
	return "unknown"
}
