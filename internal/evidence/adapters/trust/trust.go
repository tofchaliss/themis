// Package trust is Evidence's trust gate: it fingerprints a raw uploaded artifact,
// optionally verifies a caller-supplied expected checksum, checks the payload is
// well-formed, and captures provenance — producing the trust inputs the Register
// use case needs (EDR-EVIDENCE-01 D2/D3).
//
// Per-format JSON-schema validation is intentionally left to the parser ACL, which
// validates the spec version and document structure; this gate's structural check
// is the well-formed-JSON baseline — plus, for a scanner report, the curated SHAPE
// (EDR-INTAKE-01 D11). That one addition is deliberate and narrow: `POST /evidence`
// is the door everything already uses, and `json.Valid` being the whole of its
// structural check is how an array-shaped Cortex export was filed as a curated
// report on 2026-10-05 and halted Knowledge's evidence stream for 31 hours. Intake
// is the good road, but the poison class must not remain reachable through the old
// one.
package trust

import (
	"bytes"
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

	if a.Kind == domain.KindScannerReport {
		if reason, bad := curatedShapeFault(a.Raw); bad {
			return reject(fp, a.Provenance, reason), nil
		}
	}

	return Result{Fingerprint: IdentityFingerprint(fp, a.Provenance.SourceDigest), Status: domain.TrustAccepted, Provenance: a.Provenance}, nil
}

// convertedIdentityTag versions the identity rule below, so a later change of rule cannot
// produce a fingerprint that collides with this one.
const convertedIdentityTag = "themis-converted-v1"

// IdentityFingerprint is the dedup identity of a filed document (EDR-INTAKE-01, 2026-10-26
// amendment D3b). A standards SBOM that was not converted keeps the plain content fingerprint:
// its bytes ARE the evidence. A CONVERTED document also names the file it came from, because
// two different scans can convert to the same bytes — every report with zero kept findings is
// `{"findings":[]}`, so the second clean scan of another release was refused as
// `duplicate_other_release`. The same source to the same release still dedups, and the same
// source to another release is still refused: both inputs of the hash are equal. A curated
// report passed through unchanged has a source digest equal to its content fingerprint, and
// keeps the plain one, so the old door and intake still agree on its identity.
func IdentityFingerprint(content value.ContentFingerprint, sourceDigest string) value.ContentFingerprint {
	if sourceDigest == "" || sourceDigest == content.String() {
		return content
	}
	return value.NewContentFingerprint([]byte(convertedIdentityTag + "\n" + sourceDigest + "\n" + content.String()))
}

// curatedShapeFault is the cheap half of E1: a scanner report filed here is read by
// Knowledge as `{"findings":[…]}`, so a document of any other shape is one no
// consumer can read, and filing it is filing a document that will be fetched,
// re-fetched and never understood.
//
// It is a SHAPE check and nothing more. The per-finding contract belongs to the
// converter ACL and to Knowledge's scanner source, which skip and COUNT a record
// they cannot decode — one malformed finding must not void a 400-finding report, so
// a border stricter than the consumer would refuse reports the pipeline has always
// read. What is refused here is the class with no readable findings at all.
func curatedShapeFault(raw []byte) (string, bool) {
	var env struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		// Well-formed JSON that is not an object carrying `findings` — a bare array
		// is the 2026-10-05 body exactly.
		return "a scanner report is a JSON object {\"findings\":[…]}; this payload is a different shape " +
			"(a bare array of vendor records is a request encoding, not an evidence document — send it to /intake)", true
	}
	if env.Findings == nil {
		return "a scanner report needs a \"findings\" array; this payload carries none", true
	}
	for i, f := range env.Findings {
		// Each element is already a well-formed JSON value — the unmarshal above
		// said so — so its first structural byte decides, and nothing is decoded.
		// HasPrefix rather than f[0] because 0, 1 and >1 bytes are three
		// cardinalities and only one of them indexes safely (CONVENTIONS R5).
		if !bytes.HasPrefix(f, []byte("{")) {
			return fmt.Sprintf("findings[%d] is not an object", i), true
		}
	}
	return "", false
}

func reject(fp value.ContentFingerprint, prov domain.Provenance, reason string) Result {
	return Result{Fingerprint: fp, Status: domain.TrustRejected, Provenance: prov, Reason: reason}
}
