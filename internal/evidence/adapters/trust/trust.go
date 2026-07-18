// Package trust is Evidence's trust gate: it fingerprints a raw uploaded artifact,
// optionally verifies a caller-supplied expected checksum, checks the payload is
// well-formed, and captures provenance — producing the trust inputs the Register
// use case needs (EDR-EVIDENCE-01 D2/D3).
//
// Per-format JSON-schema validation is intentionally left to the parser ACL, which
// validates the spec version and document structure; this gate's structural check
// is the well-formed-JSON baseline.
package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Artifact is a raw uploaded document presented to the trust gate.
type Artifact struct {
	Raw              []byte
	Kind             domain.Kind
	ExpectedChecksum string // optional lowercase-hex SHA-256 to verify against
	Provenance       domain.Provenance
}

// Result is the trust gate's verdict. Reason is populated when Status is rejected.
type Result struct {
	Fingerprint value.ContentFingerprint
	Status      domain.TrustStatus
	Provenance  domain.Provenance
	Reason      string
}

// Gate fingerprints and validates raw artifacts.
type Gate struct{}

// Admit fingerprints the artifact, verifies the expected checksum (if any) and that
// the payload is well-formed JSON, and returns the trust verdict. A malformed or
// mismatched artifact is rejected (not an error); an empty artifact is an error.
func (Gate) Admit(a Artifact) (Result, error) {
	if len(a.Raw) == 0 {
		return Result{}, errors.New("trust: empty artifact")
	}
	if !a.Kind.Valid() {
		return Result{}, fmt.Errorf("trust: invalid kind %q", a.Kind)
	}

	fp := value.NewContentFingerprint(a.Raw)

	if a.ExpectedChecksum != "" {
		expected := strings.ToLower(strings.TrimSpace(a.ExpectedChecksum))
		if expected != fp.String() {
			return reject(fp, a.Provenance, fmt.Sprintf("checksum mismatch: expected %s, computed %s", expected, fp.String())), nil
		}
	}

	if !json.Valid(a.Raw) {
		return reject(fp, a.Provenance, "payload is not well-formed JSON"), nil
	}

	return Result{Fingerprint: fp, Status: domain.TrustAccepted, Provenance: a.Provenance}, nil
}

func reject(fp value.ContentFingerprint, prov domain.Provenance, reason string) Result {
	return Result{Fingerprint: fp, Status: domain.TrustRejected, Provenance: prov, Reason: reason}
}
