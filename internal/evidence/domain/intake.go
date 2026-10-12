package domain

import (
	"errors"
	"fmt"
)

// RejectReason is the closed taxonomy of intake refusals (EDR-INTAKE-01 D11). Every
// refusal names itself, and the set is CLOSED: adding a value is a contract change,
// which is what `TestIntakeReasonTaxonomyIsClosed` makes impossible to do quietly.
//
// The cost of the open version is on record (#116): a consumer that knew 6 of 15
// reasons reported "no reason given" for the other nine, so a refusal the system had
// named precisely reached the operator as silence.
//
// A reason is never concatenated with its elaboration. They are TWO fields — the
// reason a consumer switches on, and the detail it displays — because Governance
// flattened exactly this pair into `"<reason>: <detail>"`, turning a closed enum into
// free text and making every table lookup miss (fixed 2026-09-22).
type RejectReason string

// D11's table, in its order. Each is one reason the intake door refuses by name,
// before anything is filed.
const (
	// ReasonUnknownRelease — `release_id` or the {product,project,version} triple
	// does not resolve (D7: intake resolves, it never creates identity).
	ReasonUnknownRelease RejectReason = "unknown_release"
	// ReasonNoInventoryForRelease — D6: no SBOM-derived inventory for the release and
	// no `allow_without_sbom`.
	ReasonNoInventoryForRelease RejectReason = "no_inventory_for_release"
	// ReasonUnrecognisedFormat — D5a's detection table did not match.
	ReasonUnrecognisedFormat RejectReason = "unrecognised_format"
	// ReasonDeclaredFormatMismatch — D5a: a declared kind/format contradicts the body,
	// or is an invalid combination. Never a silent override.
	ReasonDeclaredFormatMismatch RejectReason = "declared_format_mismatch"
	// ReasonMalformedBody — not well-formed JSON, unparseable CSV, invalid UTF-8.
	ReasonMalformedBody RejectReason = "malformed_body"
	// ReasonSourceInvalid — D5b: a recognised dialect whose INPUT failed its rules;
	// the detail names the element index or CSV row.
	ReasonSourceInvalid RejectReason = "source_invalid"
	// ReasonSchemaInvalid — the converted OUTPUT failed the curated/SBOM contract.
	// This is E1, and it is the decision that closes the 2026-10-05 incident.
	ReasonSchemaInvalid RejectReason = "schema_invalid"
	// ReasonEmptyReport — zero findings, an empty array, or an SBOM with no components.
	ReasonEmptyReport RejectReason = "empty_report"
	// ReasonObservedAtUnderivable — D3: no derivable timestamp and none supplied.
	// Never `now`.
	ReasonObservedAtUnderivable RejectReason = "observed_at_underivable"
	// ReasonObservedAtInvalid — a timestamp was present but unparseable or implausible.
	ReasonObservedAtInvalid RejectReason = "observed_at_invalid"
	// ReasonConversionFailed — the dialect was valid but no finding survived translation.
	ReasonConversionFailed RejectReason = "conversion_failed"
	// ReasonChecksumMismatch — `expected_checksum` does not match the submitted bytes.
	ReasonChecksumMismatch RejectReason = "checksum_mismatch"
	// ReasonDuplicateOtherRelease — D8: byte-identical content is already filed against
	// a different release.
	ReasonDuplicateOtherRelease RejectReason = "duplicate_other_release"
	// ReasonPayloadTooLarge — over the body bound (D13).
	ReasonPayloadTooLarge RejectReason = "payload_too_large"
	// ReasonTooManyRecords — over the record bound (D13).
	ReasonTooManyRecords RejectReason = "too_many_records"
	// ReasonUnauthorized — inbound-edge auth (EDR-SECURITY-01 F1).
	ReasonUnauthorized RejectReason = "unauthorized"
)

// AllRejectReasons returns the closed taxonomy, in D11's order. It is the single
// source of truth for the set: [RejectReason.Valid] walks it, the guard test compares
// it against the documented identifiers, and a reason absent from it does not exist.
//
// A fresh slice is returned each call so no caller can grow the taxonomy by writing
// to a package variable.
//
// There is deliberately no `inventory_not_ready` (D6): Evidence has no window in
// which it holds an SBOM whose inventory is pending — `Register` parses inline and
// `Save` writes the row with its inventory in one transaction — so the value could
// never fire. A closed enum with a dead value is worse than no value: consumers write
// handling for a state that does not exist.
func AllRejectReasons() []RejectReason {
	return []RejectReason{
		ReasonUnknownRelease,
		ReasonNoInventoryForRelease,
		ReasonUnrecognisedFormat,
		ReasonDeclaredFormatMismatch,
		ReasonMalformedBody,
		ReasonSourceInvalid,
		ReasonSchemaInvalid,
		ReasonEmptyReport,
		ReasonObservedAtUnderivable,
		ReasonObservedAtInvalid,
		ReasonConversionFailed,
		ReasonChecksumMismatch,
		ReasonDuplicateOtherRelease,
		ReasonPayloadTooLarge,
		ReasonTooManyRecords,
		ReasonUnauthorized,
	}
}

// Valid reports whether r is one of the closed taxonomy's reasons.
func (r RejectReason) Valid() bool {
	for _, known := range AllRejectReasons() {
		if r == known {
			return true
		}
	}
	return false
}

// RejectError carries one reason and its elaboration across a port boundary, so a
// collaborator outside the domain (the converter ACL, a resolver) can report a
// refusal BY NAME without the inner rings learning its vocabulary.
//
// The two fields stay separate. Error() joins them for a log line only — a consumer
// reads Reason and Detail, and nothing parses the string back apart.
type RejectError struct {
	Reason RejectReason
	Detail string
}

func (e *RejectError) Error() string { return string(e.Reason) + ": " + e.Detail }

// Reject builds a reason-carrying refusal.
func Reject(reason RejectReason, detail string) error {
	return &RejectError{Reason: reason, Detail: detail}
}

// AsReject reports the refusal an error carries, if it carries one. An error that
// names no reason is an infrastructure fault, not a refusal, and the caller must not
// invent a reason for it.
func AsReject(err error) (*RejectError, bool) {
	var re *RejectError
	if errors.As(err, &re) {
		return re, true
	}
	return nil, false
}

// ReceiptStatus is where one intake attempt has got to (EDR-INTAKE-01 D9). Every
// intake is addressable, including a refused one: a rejected receipt is the thing
// that was missing on 2026-10-05, when a body was filed unreadable and nothing
// recorded that anyone had tried.
type ReceiptStatus string

// The ladder, and its three terminals.
const (
	ReceiptAccepted    ReceiptStatus = "accepted"
	ReceiptValidating  ReceiptStatus = "validating"
	ReceiptConverting  ReceiptStatus = "converting"
	ReceiptRegistering ReceiptStatus = "registering"
	ReceiptFiled       ReceiptStatus = "filed"
	ReceiptRejected    ReceiptStatus = "rejected"
	ReceiptFailed      ReceiptStatus = "failed"
)

// receiptRank orders the forward-only ladder. Terminals and the zero status are off
// the ladder at 0; terminality is checked before the rank ever is.
//
// It is a rank rather than a predecessor table because a stage may be SKIPPED: an
// SBOM is identified, never converted, so it goes validating → registering and that
// is not a defect. What is forbidden is going backwards, which is what a rank
// comparison states exactly once.
func receiptRank(s ReceiptStatus) int {
	switch s {
	case ReceiptAccepted:
		return 1
	case ReceiptValidating:
		return 2
	case ReceiptConverting:
		return 3
	case ReceiptRegistering:
		return 4
	case ReceiptFiled:
		return 5
	default:
		return 0
	}
}

// Receipt is the record of one intake attempt: its status, what the body was
// identified as, and — when terminal — the outcome. It is the only thing a refused
// intake leaves behind, because steps 1-6 of the intake are side-effect-free and
// only filing writes (D13: nothing partial is ever persisted).
//
// The zero Receipt is usable: [Receipt.Accept] is its one legal first transition.
type Receipt struct {
	status          ReceiptStatus
	reason          RejectReason
	detail          string
	evidenceID      string
	created         bool
	detectedKind    string
	detectedFormat  string
	releaseID       string
	convertedBy     string
	sourceDigest    string
	findingsTotal   int
	findingsSkipped int
}

// Status returns where the attempt has got to.
func (r *Receipt) Status() ReceiptStatus { return r.status }

// Reason returns the refusal's reason, empty unless the receipt is rejected.
func (r *Receipt) Reason() RejectReason { return r.reason }

// Detail returns the refusal's or failure's elaboration — never concatenated with
// the reason (D9/D11).
func (r *Receipt) Detail() string { return r.detail }

// EvidenceID returns the filed document's identity, empty unless filed.
func (r *Receipt) EvidenceID() string { return r.evidenceID }

// Created reports whether filing produced a new document (false = a byte-identical
// re-upload resolved to the one already held, D8).
func (r *Receipt) Created() bool { return r.created }

// DetectedKind returns what the body was identified as (D5a, echoed to the client).
func (r *Receipt) DetectedKind() string { return r.detectedKind }

// DetectedFormat returns the dialect the body was identified as (D5a).
func (r *Receipt) DetectedFormat() string { return r.detectedFormat }

// ReleaseID returns the release the attempt resolved, empty when it was refused
// before resolution ever happened (D7).
func (r *Receipt) ReleaseID() string { return r.releaseID }

// ConvertedBy returns the converter and version that produced the filed document
// ("cortex@1"), empty when the submitted bytes were filed unchanged (D2).
func (r *Receipt) ConvertedBy() string { return r.convertedBy }

// SourceDigest returns the SHA-256 of the SUBMITTED bytes — which, for a converted
// submission, are not the bytes filed (D2).
func (r *Receipt) SourceDigest() string { return r.sourceDigest }

// FindingsTotal returns how many source records the conversion considered, and
// [Receipt.FindingsSkipped] how many of them a row-level skip rule refused. Both are
// reported, never just the kept count: "427 of 427" and "427 of 500" must not look
// alike, which is the whole of the silent-skip class (KN-SCAN-OBS-1).
func (r *Receipt) FindingsTotal() int { return r.findingsTotal }

// FindingsSkipped returns how many source records the converter skipped.
func (r *Receipt) FindingsSkipped() int { return r.findingsSkipped }

// IsTerminal reports whether the attempt has reached an outcome. A terminal receipt
// is immutable: it is the record of what happened, and a record that can still change
// is not one.
func (r *Receipt) IsTerminal() bool {
	switch r.status {
	case ReceiptFiled, ReceiptRejected, ReceiptFailed:
		return true
	default:
		return false
	}
}

// Accept opens the receipt. It is legal only as the first transition.
func (r *Receipt) Accept() error { return r.advance(ReceiptAccepted) }

// StartValidating enters identification and validation (D5 stages 1-2).
func (r *Receipt) StartValidating() error { return r.advance(ReceiptValidating) }

// StartConverting enters conversion (D2/D3). Skipped for an SBOM, which is already a
// standards document.
func (r *Receipt) StartConverting() error { return r.advance(ReceiptConverting) }

// StartRegistering enters the one step that writes.
func (r *Receipt) StartRegistering() error { return r.advance(ReceiptRegistering) }

// Filed records the successful outcome. An empty evidence id is refused: a receipt
// that says `filed` and names no document is the shape of the 2026-10-05 report —
// something claimed to have landed, with nothing to point at.
func (r *Receipt) Filed(evidenceID string, created bool) error {
	if evidenceID == "" {
		return errors.New("intake: a filed receipt must name the evidence it filed")
	}
	if err := r.advance(ReceiptFiled); err != nil {
		return err
	}
	r.evidenceID = evidenceID
	r.created = created
	return nil
}

// Rejected records a refusal by name. The reason must be in the closed taxonomy —
// an unnamed refusal is the defect D11 exists to prevent.
func (r *Receipt) Rejected(reason RejectReason, detail string) error {
	if !reason.Valid() {
		return fmt.Errorf("intake: %q is not a reason in the closed taxonomy", reason)
	}
	if err := r.terminate(ReceiptRejected); err != nil {
		return err
	}
	r.reason = reason
	r.detail = detail
	return nil
}

// Failed records that the attempt could not be carried out — an infrastructure fault,
// which is NOT a refusal and therefore carries no reason. The distinction is the
// point: a refusal is a statement about the document, a failure is a statement about
// Themis.
func (r *Receipt) Failed(detail string) error {
	if err := r.terminate(ReceiptFailed); err != nil {
		return err
	}
	r.detail = detail
	return nil
}

// RecordDetected notes what the body was identified as, so the client always sees
// what Themis decided (D5a). It is not a ladder step — identification is reported
// alongside whatever the attempt goes on to do.
func (r *Receipt) RecordDetected(kind, format string) error {
	if r.IsTerminal() {
		return r.terminalError("recording a detected format")
	}
	r.detectedKind = kind
	r.detectedFormat = format
	return nil
}

// RecordRelease notes the release the attempt resolved onto (D7). Like
// [Receipt.RecordDetected] it is not a ladder step: resolution is reported alongside
// whatever the attempt goes on to do, and it is recorded even when the attempt is
// then refused — a refusal that names no release leaves the operator guessing which
// release they just failed to update.
func (r *Receipt) RecordRelease(releaseID string) error {
	if r.IsTerminal() {
		return r.terminalError("recording the resolved release")
	}
	r.releaseID = releaseID
	return nil
}

// RecordConversion notes what the conversion produced: the converter that ran, the
// digest of the bytes that arrived, and both record counts.
//
// It is recorded BEFORE the outcome is known, so a report that converted cleanly and
// was then refused still reports what the conversion saw. That ordering is the point:
// "427 of 427 converted, then refused as schema_invalid" and "refused, we have no
// idea what was in it" are different facts, and only the first one is actionable.
func (r *Receipt) RecordConversion(convertedBy, sourceDigest string, findingsTotal, findingsSkipped int) error {
	if r.IsTerminal() {
		return r.terminalError("recording a conversion")
	}
	r.convertedBy, r.sourceDigest = convertedBy, sourceDigest
	r.findingsTotal, r.findingsSkipped = findingsTotal, findingsSkipped
	return nil
}

// advance walks the forward-only ladder.
func (r *Receipt) advance(to ReceiptStatus) error {
	if r.IsTerminal() {
		return r.terminalError(string(to))
	}
	// The ladder has ONE entrance. Without this, a rank comparison alone would let a
	// receipt start at `registering` — an attempt that was never accepted, yet is
	// writing.
	if r.status == "" && to != ReceiptAccepted {
		return fmt.Errorf("intake: a receipt enters the ladder at %q, not %q", ReceiptAccepted, to)
	}
	if receiptRank(to) <= receiptRank(r.status) {
		return fmt.Errorf("intake: illegal receipt transition %q -> %q; the ladder is forward-only", r.status, to)
	}
	r.status = to
	return nil
}

// terminate reaches one of the two off-ladder terminals, which are legal from any
// non-terminal status: an attempt can be refused or fail at any point.
func (r *Receipt) terminate(to ReceiptStatus) error {
	if r.IsTerminal() {
		return r.terminalError(string(to))
	}
	r.status = to
	return nil
}

func (r *Receipt) terminalError(what string) error {
	return fmt.Errorf("intake: receipt is terminal at %q; %s would rewrite a finished record", r.status, what)
}
