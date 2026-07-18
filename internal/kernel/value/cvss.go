package value

import (
	"fmt"
	"strings"
)

// CVSS is a Common Vulnerability Scoring System verdict: a base score in [0.0, 10.0]
// and its (optional) vector string. It records what a source reported and derives the
// qualitative Severity band; it does not recompute the score from the vector — Themis
// treats the source's score as given (reconciliation of competing scores is a
// Knowledge concern, not a kernel one).
type CVSS struct {
	score  float64
	vector string
}

// NewCVSS validates and constructs a CVSS value. The base score must lie within
// [0.0, 10.0]; the vector is optional and stored trimmed.
func NewCVSS(score float64, vector string) (CVSS, error) {
	if score < 0 || score > 10 {
		return CVSS{}, fmt.Errorf("cvss: score %.1f out of range [0.0, 10.0]", score)
	}
	return CVSS{score: score, vector: strings.TrimSpace(vector)}, nil
}

// Score returns the CVSS base score.
func (c CVSS) Score() float64 { return c.score }

// Vector returns the CVSS vector string (may be empty).
func (c CVSS) Vector() string { return c.vector }

// Severity returns the qualitative band derived from the base score.
func (c CVSS) Severity() Severity { return SeverityFromCVSSScore(c.score) }

// IsZero reports whether the value carries neither a score nor a vector.
func (c CVSS) IsZero() bool { return c.score == 0 && c.vector == "" }
