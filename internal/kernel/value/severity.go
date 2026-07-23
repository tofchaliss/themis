package value

import "strings"

// Severity is the qualitative severity rating of a vulnerability. It is a controlled
// value: ParseSeverity folds feed-supplied labels into it, and SeverityFromCVSSScore
// derives the band from a CVSS base score (the standard CVSS v3 qualitative scale).
type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid reports whether s is a recognized severity.
func (s Severity) Valid() bool {
	switch s {
	case SeverityUnknown, SeverityNone, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// String returns the severity label.
func (s Severity) String() string { return string(s) }

// ParseSeverity canonicalizes a feed-supplied severity label (case-insensitive,
// including vendor synonyms). A blank or unrecognized value maps to SeverityUnknown,
// so a missing severity never becomes a stray empty bucket.
func ParseSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "none":
		return SeverityNone
	case "low":
		return SeverityLow
	case "medium", "moderate":
		return SeverityMedium
	case "high", "important":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

// SeverityFromCVSSScore maps a CVSS base score to its qualitative band per the
// CVSS v3.x specification. An out-of-range score returns SeverityUnknown.
func SeverityFromCVSSScore(score float64) Severity {
	switch {
	case score < 0 || score > 10:
		return SeverityUnknown
	case score == 0:
		return SeverityNone
	case score < 4.0:
		return SeverityLow
	case score < 7.0:
		return SeverityMedium
	case score < 9.0:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}
