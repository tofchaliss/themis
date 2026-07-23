package value

import (
	"errors"
	"fmt"
	"strings"
)

const purlScheme = "pkg:"

// PURL is a package URL identifying a software component, e.g.
// "pkg:deb/debian/openssl@3.0.11". Themis treats the purl as an opaque component
// identity stored in its canonical string form; it does not re-derive the purl's
// fields. Construction validates only the "pkg:" scheme and a non-empty body — the
// purl spec's finer grammar is intentionally not enforced here.
type PURL struct {
	raw string
}

// NewPURL validates and constructs a PURL.
func NewPURL(raw string) (PURL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return PURL{}, errors.New("purl: empty")
	}
	if !strings.HasPrefix(s, purlScheme) {
		return PURL{}, fmt.Errorf("purl: missing %q scheme: %q", purlScheme, raw)
	}
	if strings.TrimPrefix(s, purlScheme) == "" {
		return PURL{}, fmt.Errorf("purl: empty body: %q", raw)
	}
	return PURL{raw: s}, nil
}

// String returns the canonical purl string.
func (p PURL) String() string { return p.raw }

// Equal reports whether two purls are identical.
func (p PURL) Equal(other PURL) bool { return p.raw == other.raw }

// IsZero reports whether the purl is the zero value.
func (p PURL) IsZero() bool { return p.raw == "" }
