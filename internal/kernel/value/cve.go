package value

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// CVEID is a canonical CVE identifier in CVE-YYYY-N… form. Distro-prefixed aliases
// (e.g. ALPINE-CVE-2024-1234) are normalized to their canonical CVE at construction,
// so one vulnerability always yields one identity. It is the Faultline's binding
// business key in Knowledge (EDR-KNOWLEDGE-01 D1); here it is only a validated,
// behavior-free value. Source/feed is provenance, never identity.
type CVEID struct {
	raw string
}

var cveCanonical = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

// NewCVEID normalizes and validates a CVE identifier: it trims and upper-cases the
// input, folds a known distro alias (…CVE-YYYY-N…) to its canonical CVE, and rejects
// anything that is not a canonical CVE afterwards. This ports the PoC's
// NormalizeCVEID semantics but, as a value object, requires canonical form.
func NewCVEID(raw string) (CVEID, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return CVEID{}, errors.New("cve id: empty")
	}
	if cveCanonical.MatchString(s) {
		return CVEID{raw: s}, nil
	}
	// A distro-prefixed alias carries the canonical CVE as a suffix, e.g.
	// ALPINE-CVE-2024-1234 → CVE-2024-1234.
	if idx := strings.Index(s, "CVE-"); idx > 0 {
		if candidate := s[idx:]; cveCanonical.MatchString(candidate) {
			return CVEID{raw: candidate}, nil
		}
	}
	return CVEID{}, fmt.Errorf("cve id: not a canonical CVE identifier: %q", raw)
}

// String returns the canonical CVE identifier.
func (c CVEID) String() string { return c.raw }

// Equal reports whether two CVE identifiers are the same.
func (c CVEID) Equal(other CVEID) bool { return c.raw == other.raw }

// IsZero reports whether the CVE identifier is the zero value.
func (c CVEID) IsZero() bool { return c.raw == "" }
