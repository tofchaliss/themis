// Package value holds the shared, behavior-free ubiquitous-language value objects
// spoken by every Themis bounded context. Today it provides the content
// fingerprint and the package URL (purl); phase3-shared-kernel adds the CVE-ID,
// CVSS, and severity.
//
// Admission rule (EDR-KERNEL-01 D3): a member lives here only if it is (1) used by
// every stage, (2) stable, (3) owned by no single context, and (4) behavior-free —
// pure construction and validation only. The package imports nothing but the
// standard library.
package value

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// ContentFingerprint is the SHA-256 digest of a blob of bytes, rendered as
// lowercase hex. It provides content-addressed identity: identical bytes always
// produce an equal fingerprint, and any difference produces a different one.
type ContentFingerprint struct {
	hex string
}

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NewContentFingerprint computes the SHA-256 fingerprint of raw.
func NewContentFingerprint(raw []byte) ContentFingerprint {
	sum := sha256.Sum256(raw)
	return ContentFingerprint{hex: hex.EncodeToString(sum[:])}
}

// ParseContentFingerprint reconstructs a fingerprint from its stored lowercase-hex
// SHA-256 string (e.g. when loading a persisted Evidence record). It rejects any
// value that is not exactly 64 lowercase hex characters.
func ParseContentFingerprint(s string) (ContentFingerprint, error) {
	if !hexSHA256.MatchString(s) {
		return ContentFingerprint{}, fmt.Errorf("content fingerprint: not a lowercase-hex SHA-256: %q", s)
	}
	return ContentFingerprint{hex: s}, nil
}

// String returns the lowercase-hex SHA-256 digest.
func (f ContentFingerprint) String() string { return f.hex }

// Equal reports whether two fingerprints are identical.
func (f ContentFingerprint) Equal(other ContentFingerprint) bool { return f.hex == other.hex }

// IsZero reports whether the fingerprint is the zero value (nothing hashed).
func (f ContentFingerprint) IsZero() bool { return f.hex == "" }
