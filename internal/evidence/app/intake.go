package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// The ACL's kind vocabulary (EDR-INTAKE-01 D5a). It names what the BODY is, which is
// not the same question as what a FILED document is: Evidence files `sbom`, `vex` and
// `scanner-report`, while the door identifies `sbom` and `vuln-report`.
const (
	detectedKindSBOM   = "sbom"
	detectedKindReport = "vuln-report"
)

// defaultIntakeMaxBytes is D13's body bound (`THEMIS_INTAKE_MAX_BYTES`), applied when
// a caller wires no limit. A border is protected by bounds, not by a format check, so
// there is no "unlimited" setting here.
const defaultIntakeMaxBytes int64 = 64 << 20

// IntakeCommand is one submission at the single intake door (D1): the artifact as raw
// bytes, plus the metadata that used to be envelope fields.
type IntakeCommand struct {
	// ContentType is the submitted header. It is decisive for CSV and otherwise only
	// a hint — the body is the evidence of what the body is.
	ContentType string
	// Body is the artifact itself, unwrapped. `POST /evidence` wraps a document in a
	// JSON envelope, which forces a client to JSON-escape an entire SBOM; here the
	// body IS the artifact, which is what makes `--data-binary @file` the whole client.
	Body []byte
	// Product, Project and Version name the release by its triple; ReleaseID names it
	// directly. Either road, resolved read-only (D7).
	Product string
	Project string
	Version string
	// ReleaseID is the direct road, and wins when supplied — the resolver decides.
	ReleaseID string
	// ObservedAt is the caller's assertion about WHICH observation this is. Zero means
	// derive it from the body; it is never the upload time (D3).
	ObservedAt time.Time
	// AllowWithoutSBOM is D6's deliberate override, recorded in provenance so a
	// release whose findings rest on no inventory says so.
	AllowWithoutSBOM bool
	// ProvenanceSource and ProvenanceImageDigest carry the same meanings they have
	// on `POST /evidence`: who produced the document (labeling only, never
	// authority) and the scanned image's digest. The digest is recorded rather than
	// checked — intake cannot tell a new image from a new report on the old one
	// (D8), so the most it can do is make the mismatch visible later.
	ProvenanceSource      string
	ProvenanceImageDigest string
}

// IntakeService is the one intake door's use case (EDR-INTAKE-01 D1): it identifies a
// submitted document, resolves its release, converts a vendor dialect into the curated
// document Themis files, validates what it is about to file, and files it through the
// existing Register path.
//
// The ORDER is the contract, and so is where the writing starts — see [IntakeService.Intake].
type IntakeService struct {
	maxBytes  int64
	releases  ReleaseResolver
	inventory InventoryReader
	reports   ReportRegistry
	registrar EvidenceRegistrar
}

// NewIntakeService wires the intake ports. A maxBytes of zero or less takes D13's
// default rather than meaning "no bound".
func NewIntakeService(maxBytes int64, releases ReleaseResolver, inventory InventoryReader, reports ReportRegistry, registrar EvidenceRegistrar) *IntakeService {
	if maxBytes <= 0 {
		maxBytes = defaultIntakeMaxBytes
	}
	return &IntakeService{maxBytes: maxBytes, releases: releases, inventory: inventory, reports: reports, registrar: registrar}
}

// Intake runs the door's seven steps, in this order, and the order is the decision
// (design.md "Ordering inside app.Intake, and why"):
//
//  1. size — a bound before anything is read into the domain.
//  2. detect — the cheapest discriminator; a body we cannot name gets no further.
//  3. resolve the release — before conversion, because converting for a release that
//     does not exist is wasted work on the common typo.
//  4. convert — the vendor dialect becomes the curated document (an SBOM is already a
//     standards document and passes straight through).
//  5. validate what will be FILED — E1. On the converted document, because that is
//     what gets stored and what a consumer will read.
//  6. SBOM-first — AFTER validation, so a report that is both invalid and early
//     reports the invalidity, which is the more actionable of the two faults.
//  7. file — the existing Register path: trust gate, aggregate, persist + outbox.
//
// **The first failure wins and nothing is filed until step 7.** Steps 1-6 are
// side-effect-free, so a refused intake leaves a receipt and nothing else: no
// evidence, no event, no bus traffic (D13).
//
// Every outcome is on the receipt. The returned error is non-nil only for an
// infrastructure fault — a precondition that could not be EVALUATED, or a write that
// could not be made — which is a statement about Themis, not about the document, and
// is why those end `failed` rather than `rejected`.
func (s *IntakeService) Intake(ctx context.Context, cmd IntakeCommand) (*domain.Receipt, error) {
	r := &domain.Receipt{}

	// The ladder below is walked once, in order, by this one function, so each
	// transition is legal by construction. The state machine exists to refuse an
	// out-of-order transition from a LATER caller — Group 3's slow path resumes a
	// receipt it did not create — and that refusal is pinned by the domain's tests.
	// Checking it here would add branches no input can reach; the two transitions
	// that CAN refuse a legal caller (a filed receipt with no evidence id) are
	// checked where they happen.
	_ = r.Accept()

	// 1. Size (D13). Checked before the body is read into the domain; the HTTP edge
	// checks it again before buffering, because a limit applied after the read
	// protects nothing it was meant to.
	if int64(len(cmd.Body)) > s.maxBytes {
		return refused(r, domain.ReasonPayloadTooLarge,
			fmt.Sprintf("body is %d bytes, over the %d-byte intake limit", len(cmd.Body), s.maxBytes))
	}

	_ = r.StartValidating()

	// 2. Detect (D5a).
	kind, dialect, err := s.reports.Detect(cmd.ContentType, cmd.Body)
	if err != nil {
		return refusedByPort(r, domain.ReasonUnrecognisedFormat, err)
	}
	_ = r.RecordDetected(kind, dialect)

	// Evidence's own kind for what was detected. The ACL's table yields only the two
	// kinds below, so a third is a defect in the implementation behind the port
	// rather than a fault in the document — refused by name all the same, because
	// filing a document under a kind nobody chose is how an unreadable one lands.
	filedKind, ok := evidenceKind(kind)
	if !ok {
		return refused(r, domain.ReasonUnrecognisedFormat,
			fmt.Sprintf("detected kind %q is not a document Evidence files", kind))
	}

	// 3. Resolve the release, read-only (D7).
	releaseID, err := s.releases.Resolve(ctx, cmd.Product, cmd.Project, cmd.Version, cmd.ReleaseID)
	if err != nil {
		return refusedByPort(r, domain.ReasonUnknownRelease, err)
	}
	_ = r.RecordRelease(releaseID)

	// 4. Convert (D2/D3). An SBOM is identified, never converted: it is already a
	// standards document, its bytes ARE the evidence document, and re-serializing it
	// would change the fingerprint that dedups a re-upload.
	curated, stats := cmd.Body, ReportStats{}
	prov := domain.Provenance{Source: cmd.ProvenanceSource, ImageDigest: cmd.ProvenanceImageDigest}
	if filedKind != domain.KindSBOM {
		_ = r.StartConverting()
		out, st, convertedBy, sourceDigest, cerr := s.reports.Convert(dialect, cmd.Body, cmd.ObservedAt)
		if cerr != nil {
			return refusedByPort(r, domain.ReasonConversionFailed, cerr)
		}
		curated, stats = out, st
		prov.ConvertedBy, prov.SourceDigest = convertedBy, sourceDigest
		_ = r.RecordConversion(convertedBy, sourceDigest, st.FindingsTotal, st.FindingsSkipped)
	}

	// 5. Validate what will be filed — E1, the decision that closes the 2026-10-05
	// incident. The old door's whole structural check was `json.Valid`, which the
	// array-shaped Cortex export passed; it was filed unreadable and halted
	// Knowledge's evidence stream for 31 hours.
	if reason, detail, bad := validateFiled(filedKind, curated, stats); bad {
		return refused(r, reason, detail)
	}

	// 6. SBOM-first (D6) — for a vulnerability report only. An SBOM cannot require an
	// inventory to already exist: it is the thing that creates one.
	if filedKind != domain.KindSBOM {
		has, ierr := s.inventory.HasInventory(ctx, releaseID)
		if ierr != nil {
			// A precondition that could not be EVALUATED is not a precondition that
			// failed. Reporting `no_inventory_for_release` here would tell the
			// operator to upload an SBOM they have already uploaded.
			return failed(r, fmt.Sprintf("could not read the release's inventory: %v", ierr), ierr)
		}
		if !has {
			if !cmd.AllowWithoutSBOM {
				return refused(r, domain.ReasonNoInventoryForRelease,
					fmt.Sprintf("release %s has no SBOM-derived inventory; upload the SBOM first, or resend with allow_without_sbom=true", releaseID))
			}
			prov.WithoutSBOM = true
		}
	}

	// 7. File. The only step that writes, and it writes the aggregate with its outbox
	// note in one transaction.
	_ = r.StartRegistering()
	res, err := s.registrar.Register(ctx, RegisterCommand{
		Raw:              curated,
		Kind:             filedKind,
		Format:           dialect,
		SubjectReleaseID: releaseID,
		Provenance:       prov,
	})
	if err != nil {
		return failed(r, fmt.Sprintf("register: %v", err), err)
	}
	if ferr := r.Filed(string(res.ID), res.Created); ferr != nil {
		// The write reported success without naming a document. "Filed, pointing at
		// nothing" is the 2026-10-05 shape, so the receipt says `failed` instead of
		// claiming an id it does not have.
		return failed(r, ferr.Error(), ferr)
	}
	return r, nil
}

// evidenceKind maps the ACL's detected kind onto the kind Evidence files. A
// vulnerability report in any dialect is filed as one `scanner-report`, which is what
// makes the dialect a request encoding rather than a document type (D2).
func evidenceKind(detected string) (domain.Kind, bool) {
	switch detected {
	case detectedKindSBOM:
		return domain.KindSBOM, true
	case detectedKindReport:
		return domain.KindScannerReport, true
	default:
		return "", false
	}
}

// validateFiled is E1's cheap half, applied to the document about to be filed.
//
// It is deliberately a SHAPE check and not full schema validation: the curated
// contract's per-field rules belong to the converter ACL, which already applies them
// and counts what it skipped, and a border stricter than the consumer would refuse
// reports the pipeline has always read — which is its own outage. What is checked here
// is the class no consumer can read at all: a document that is not the shape its kind
// claims.
func validateFiled(kind domain.Kind, doc []byte, stats ReportStats) (domain.RejectReason, string, bool) {
	if !isJSONObject(doc) {
		return domain.ReasonSchemaInvalid, fmt.Sprintf(
			"a filed %s document is a JSON object, and this one is not — a bare array or scalar is the 2026-10-05 shape", kind), true
	}
	if kind == domain.KindSBOM {
		// An SBOM's structure is the parser ACL's to validate, and an SBOM with zero
		// components cannot be filed at all (the aggregate refuses it), so there is
		// nothing further for the border to add.
		return "", "", false
	}

	var env struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(doc, &env); err != nil || env.Findings == nil {
		return domain.ReasonSchemaInvalid,
			"a curated scanner report is a JSON object {\"findings\":[…]}; this document carries no \"findings\" array", true
	}
	for i, f := range env.Findings {
		if !isJSONObject(f) {
			return domain.ReasonSchemaInvalid, fmt.Sprintf("findings[%d] is not an object", i), true
		}
	}
	if stats.FindingsTotal == 0 {
		return domain.ReasonEmptyReport,
			"the report names zero observations — nothing would be filed but an empty document", true
	}
	return "", "", false
}

// isJSONObject reports whether doc is a JSON object. It decodes nothing: a 60 MB SBOM
// costs one byte to classify.
func isJSONObject(doc []byte) bool {
	for _, b := range doc {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// refused records a refusal and returns NO error: a refusal is a complete, truthful
// outcome reported ON the receipt — the document was read, understood and declined —
// and not something the caller has to interpret from an error.
func refused(r *domain.Receipt, reason domain.RejectReason, detail string) (*domain.Receipt, error) {
	_ = r.Rejected(reason, detail)
	return r, nil
}

// refusedByPort records the refusal a port error carries, falling back to the step's
// own reason when the error names none. The fallback matters: an error carrying no
// reason is an infrastructure fault, and naming the step it failed in is the most
// honest thing that can be said without inventing a diagnosis.
func refusedByPort(r *domain.Receipt, fallback domain.RejectReason, err error) (*domain.Receipt, error) {
	if re, ok := domain.AsReject(err); ok {
		return refused(r, re.Reason, re.Detail)
	}
	return refused(r, fallback, err.Error())
}

// failed records that Themis could not carry the attempt out, and returns the cause
// so the adapter that owns logging can say what happened (the app ring never logs,
// CONVENTIONS R1).
func failed(r *domain.Receipt, detail string, cause error) (*domain.Receipt, error) {
	_ = r.Failed(detail)
	return r, cause
}
