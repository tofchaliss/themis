package domain

import (
	"errors"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Kind labels what an Evidence record contains.
type Kind string

const (
	KindSBOM          Kind = "sbom"
	KindVEX           Kind = "vex"
	KindScannerReport Kind = "scanner-report"
)

// Valid reports whether k is a recognized Evidence kind.
func (k Kind) Valid() bool {
	switch k {
	case KindSBOM, KindVEX, KindScannerReport:
		return true
	default:
		return false
	}
}

// EvidenceID is Evidence's own opaque, stable aggregate identity. It is never a
// derived or external identifier; the application layer assigns it at registration
// and returns it to the caller (EDR-EVIDENCE-01 D2).
type EvidenceID string

// TrustStatus records the outcome of the trust gate.
type TrustStatus string

const (
	TrustAccepted TrustStatus = "accepted"
	TrustRejected TrustStatus = "rejected"
)

// Valid reports whether s is a recognized trust status.
func (s TrustStatus) Valid() bool { return s == TrustAccepted || s == TrustRejected }

// SubjectRef references the Release an Evidence record describes. Evidence
// validates that the Release exists (via a port) but never owns the catalog
// (EDR-EVIDENCE-01 D5; EDR-KERNEL-01 D1/D2).
type SubjectRef struct {
	ReleaseID string
}

// Provenance records where the evidence came from — the producing tool and,
// optionally, the scanned image digest — as data, never as a modeled business
// entity (the image digest is provenance only; EDR-KERNEL-01 D2).
type Provenance struct {
	Source      string // producing tool, e.g. "trivy"
	ImageDigest string // optional; the scanned image's digest
}

// Evidence is the immutable aggregate root of the Evidence context: one filed,
// content-addressed observation about a Release. It is constructed once and never
// mutated — there are no setters.
type Evidence struct {
	id          EvidenceID
	kind        Kind
	fingerprint value.ContentFingerprint
	subject     SubjectRef
	provenance  Provenance
	trust       TrustStatus
	inventory   Inventory
	filedAt     time.Time
}

// NewEvidence constructs and validates an Evidence aggregate. An SBOM must carry a
// non-empty canonical inventory; other kinds may have an empty inventory.
func NewEvidence(
	id EvidenceID,
	kind Kind,
	fingerprint value.ContentFingerprint,
	subject SubjectRef,
	provenance Provenance,
	trust TrustStatus,
	inventory Inventory,
	filedAt time.Time,
) (Evidence, error) {
	switch {
	case id == "":
		return Evidence{}, errors.New("evidence: empty id")
	case !kind.Valid():
		return Evidence{}, fmt.Errorf("evidence: invalid kind %q", kind)
	case fingerprint.IsZero():
		return Evidence{}, errors.New("evidence: zero fingerprint")
	case subject.ReleaseID == "":
		return Evidence{}, errors.New("evidence: empty subject release id")
	case !trust.Valid():
		return Evidence{}, fmt.Errorf("evidence: invalid trust status %q", trust)
	case filedAt.IsZero():
		return Evidence{}, errors.New("evidence: zero filed-at time")
	case kind == KindSBOM && inventory.IsEmpty():
		return Evidence{}, errors.New("evidence: SBOM requires a non-empty inventory")
	}
	return Evidence{
		id:          id,
		kind:        kind,
		fingerprint: fingerprint,
		subject:     subject,
		provenance:  provenance,
		trust:       trust,
		inventory:   inventory,
		filedAt:     filedAt,
	}, nil
}

// ID returns the stable Evidence identity.
func (e Evidence) ID() EvidenceID { return e.id }

// Kind returns the evidence kind label.
func (e Evidence) Kind() Kind { return e.kind }

// Fingerprint returns the content fingerprint that identifies the raw bytes.
func (e Evidence) Fingerprint() value.ContentFingerprint { return e.fingerprint }

// Subject returns the referenced Release.
func (e Evidence) Subject() SubjectRef { return e.subject }

// Provenance returns the recorded provenance.
func (e Evidence) Provenance() Provenance { return e.provenance }

// Trust returns the trust-gate outcome.
func (e Evidence) Trust() TrustStatus { return e.trust }

// Inventory returns the canonical component inventory (empty for non-SBOM kinds).
func (e Evidence) Inventory() Inventory { return e.inventory }

// FiledAt returns the time the evidence was filed.
func (e Evidence) FiledAt() time.Time { return e.filedAt }
