package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

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
	// DeclaredKind is the caller's `kind` (`sbom` / `vuln-report`), empty when none
	// was declared. It is checked against the body, never obeyed over it; on a Nessus
	// export, which is both, it picks the road (EDR-INTAKE-01, 2026-10-26 P1).
	DeclaredKind string
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
	// CreateRelease is B2's bounded create: with the WHOLE triple, find-or-create
	// the version instead of refusing an unknown one. It is accepted only together
	// with {product, project, version} and never beside ReleaseID — see
	// [IntakeCommand.ParameterRefusal].
	CreateRelease bool
	// BuildID is which pipeline run produced this document (B5): artifact
	// provenance, at most 256 Unicode CODE POINTS, and deliberately inert —
	// nothing reads it for dedup, correlation or current-SBOM selection.
	BuildID string
	// Authorize is the caller's product confinement, supplied by the edge that
	// authenticated the request; nil means none applies (an `admin` key, or an
	// auth-disabled node). See [ProductAuthorizer].
	Authorize ProductAuthorizer
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

// buildIDMaxCodePoints is B5's bound, and the UNIT is the decision: 256 Unicode code
// points, which is what OpenAPI's / JSON Schema's `maxLength` counts, so the spec and
// this check cannot disagree about what "256" means. 256 x "é" is 512 bytes and is
// ACCEPTED; `len` would have refused it.
const buildIDMaxCodePoints = 256

// ParameterRefusal is step 1 of the intake's order (EDR-INTAKE-01 B7): the checks
// that need no body, have no side effect, and therefore run BEFORE the size bound.
// It returns the refusal, or nil when the parameters are coherent.
//
// It is exported because the HTTP edge applies it too, before it buffers the body —
// the same reason the size bound is checked in both places. A parameter fault
// discovered after a 60 MB read is a fault reported on the wrong thing: a request
// that is both oversized and carries a malformed `build_id` is told about the
// `build_id`, which is the fault the caller can actually fix. That can only happen on
// a request using the new parameters, so no existing answer moves — and
// `TestParameterValidationPrecedesTheSizeBound` holds the order as a decision rather
// than as an accident of code layout.
//
// The three faults, and why each is a 400 rather than the 422 of a document that was
// read and declined (B2's status-code table):
//
//   - `create_release` WITH `release_id` — the caller named the release two ways and
//     intake will not guess which one it meant.
//   - `create_release` without the WHOLE triple — a partial name is not something a
//     version can be created from. WITHOUT `create_release` the same partial name
//     keeps today's `404 unknown_release`, because then it is a lookup and "not
//     found" is the honest answer. The distinction is deliberate (B2's note on rows
//     5 and 6 versus row 4).
//   - `build_id` over the bound or not valid UTF-8 — refused by name and NEVER
//     truncated (B5): a provenance value we silently altered is not the value the
//     caller recorded, and provenance is the worst place to discover that later.
func (c IntakeCommand) ParameterRefusal() *domain.RejectError {
	if c.CreateRelease && c.ReleaseID != "" {
		return &domain.RejectError{
			Reason: domain.ReasonCreateReleaseConflict,
			Detail: fmt.Sprintf("create_release=true names a release to CREATE and release_id=%q names one that exists; "+
				"send the {product, project, version} triple with create_release=true, or release_id alone", c.ReleaseID),
		}
	}
	if c.CreateRelease && (c.Product == "" || c.Project == "" || c.Version == "") {
		return &domain.RejectError{
			Reason: domain.ReasonIncompleteReleaseTriple,
			Detail: fmt.Sprintf("create_release=true needs the whole {product, project, version} triple; got product=%q, project=%q, version=%q "+
				"(intake creates the version only, under a Product and Project a human already registered)", c.Product, c.Project, c.Version),
		}
	}
	if c.BuildID != "" {
		if !utf8.ValidString(c.BuildID) {
			return &domain.RejectError{
				Reason: domain.ReasonBuildIDInvalid,
				Detail: "build_id is not valid UTF-8 after decoding, so a code-point count of it is not a defined quantity; " +
					"it is refused rather than repaired",
			}
		}
		if n := utf8.RuneCountInString(c.BuildID); n > buildIDMaxCodePoints {
			return &domain.RejectError{
				Reason: domain.ReasonBuildIDInvalid,
				Detail: fmt.Sprintf("build_id is %d Unicode code points, over the %d-code-point bound; it is refused, never truncated", n, buildIDMaxCodePoints),
			}
		}
	}
	return nil
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
	provision ReleaseProvisioner
	inventory InventoryReader
	reports   ReportRegistry
	registrar EvidenceRegistrar
}

// NewIntakeService wires the intake ports. A maxBytes of zero or less takes D13's
// default rather than meaning "no bound".
//
// A nil provisioner is a node wired with no Registry write seam — the dev stub's
// posture, and any wiring that supplies none — and it is replaced by one that REFUSES
// rather than left nil. A missing seam is a misconfiguration, and the honest answer to
// one is a sentence naming it, not a panic inside the only step that writes.
func NewIntakeService(maxBytes int64, releases ReleaseResolver, provision ReleaseProvisioner, inventory InventoryReader, reports ReportRegistry, registrar EvidenceRegistrar) *IntakeService {
	if maxBytes <= 0 {
		maxBytes = defaultIntakeMaxBytes
	}
	if provision == nil {
		provision = unprovisioned{}
	}
	return &IntakeService{
		maxBytes: maxBytes, releases: releases, provision: provision,
		inventory: inventory, reports: reports, registrar: registrar,
	}
}

// unprovisioned stands in for a node that wires no Registry write seam. It can only be
// reached by a request whose resolution answered "to be created", which needs both
// `create_release=true` and a Product and Project that resolved by name — so on the
// dev stub, which knows no names, it is unreachable by construction.
type unprovisioned struct{}

func (unprovisioned) FindOrCreateRelease(context.Context, string, string) (string, bool, error) {
	return "", false, errors.New("this node wires no registry write seam, so intake cannot create a version; " +
		"register the release first, or run the node against the registry")
}

// Intake runs the door's steps, in this order, and the order is the decision
// (EDR-INTAKE-01 B7 is the authoritative list; design.md §3 restates it):
//
//  0. parameters — the checks that need no body and have no side effect, so they
//     precede the size bound (B7's step 1).
//  1. size — a bound before anything is read into the domain.
//  2. detect — the cheapest discriminator; a body we cannot name gets no further.
//  3. resolve the release AND authorize the resolved product — before conversion,
//     because converting for a release that does not exist is wasted work on the
//     common typo, and after detection, so an unidentifiable body answers `415`
//     rather than disclosing anything about which products exist.
//  4. convert — the vendor dialect becomes the curated document (an SBOM is already a
//     standards document and passes straight through).
//  5. validate what will be FILED — E1. On the converted document, because that is
//     what gets stored and what a consumer will read.
//  6. SBOM-first — AFTER validation, so a report that is both invalid and early
//     reports the invalidity, which is the more actionable of the two faults.
//  7. find-or-create the version, when resolution said it does not exist yet (B7's
//     step 8) — the FIRST step that writes anything, and it writes into Registry.
//  8. file — the existing Register path: trust gate, aggregate, persist + outbox.
//
// **The first failure wins and nothing is created or filed until step 7.** Steps 0-6
// are side-effect-free, so a refused intake leaves a receipt and nothing else: no
// release, no evidence, no event, no bus traffic (D13). That is why the create sits
// here and not with resolution: a create at step 3 would leave an empty Release behind
// every `schema_invalid` report, and a bot retrying a malformed upload would mint one
// per attempt (B2).
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

	// 0. Parameters (B7's step 1) — before the size bound, because these checks need
	// no body and have no side effect. See [IntakeCommand.ParameterRefusal].
	if refusal := cmd.ParameterRefusal(); refusal != nil {
		return refused(r, refusal.Reason, refusal.Detail)
	}

	// 1. Size (D13). Checked before the body is read into the domain; the HTTP edge
	// checks it again before buffering, because a limit applied after the read
	// protects nothing it was meant to.
	if int64(len(cmd.Body)) > s.maxBytes {
		return refused(r, domain.ReasonPayloadTooLarge,
			fmt.Sprintf("body is %d bytes, over the %d-byte intake limit", len(cmd.Body), s.maxBytes))
	}

	_ = r.StartValidating()

	// 2. Detect (D5a).
	kind, dialect, err := s.reports.Detect(cmd.ContentType, cmd.Body, cmd.DeclaredKind)
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

	// 3. Resolve the release, read-only (D7) — and AUTHORIZE the resolved product on
	// the way (B7's step 4). The authorization is here, inside resolution, because
	// the decision needs the RESOLVED product and the order is part of the contract:
	// it runs after the body was identified (so an unidentifiable body still answers
	// `415`, which discloses nothing about which products exist) and before the
	// project is looked up (so a key that may not see a product cannot learn which
	// projects it has).
	//
	// `create_release` changes what an ABSENT version means here and nothing else:
	// resolution stays read-only and answers "to be created", naming the project the
	// version will go under (B7's step 4). An unresolved Product or Project is still a
	// refusal — those names are human-owned, and a typo in one is where a parallel
	// estate comes from. The create itself is step 7 below.
	res, err := s.releases.Resolve(ctx, ResolveRequest{
		Product:       cmd.Product,
		Project:       cmd.Project,
		Version:       cmd.Version,
		ReleaseID:     cmd.ReleaseID,
		CreateRelease: cmd.CreateRelease,
		Authorize:     cmd.Authorize,
	})
	if err != nil {
		return refusedByPort(r, domain.ReasonUnknownRelease, err)
	}
	// A version still to be created has no id yet, so there is nothing to record here
	// and step 7 records it once the create answers. The guard is explicit rather than
	// resting on "recording an empty id happens to be a no-op": a receipt names the
	// release the attempt acted on, and a blank subject on a refused receipt would read
	// as "we resolved nothing" when resolution in fact succeeded.
	if res.ReleaseID != "" {
		_ = r.RecordRelease(res.ReleaseID)
	}

	// 4. Convert (D2/D3). A CycloneDX or SPDX SBOM is identified, never converted: it
	// is already a standards document, its bytes ARE the evidence document, and
	// re-serializing it would change the fingerprint that dedups a re-upload. The
	// ACL hands it back untouched with no converter named. Any other dialect —
	// a vendor report, or a Nessus export's package list (2026-10-26 P2) — is converted.
	//
	// `BuildID` is artifact provenance and travels with the other two labels (B5):
	// which pipeline run produced the document, recorded beside who produced it and
	// which image it was about. It is deliberately inert — nothing downstream reads it
	// to decide anything, which is why it can be copied here and nowhere else.
	prov := domain.Provenance{
		Source:      cmd.ProvenanceSource,
		ImageDigest: cmd.ProvenanceImageDigest,
		BuildID:     cmd.BuildID,
	}
	_ = r.StartConverting()
	conv, cerr := s.reports.Convert(kind, dialect, cmd.Body, cmd.ObservedAt)
	if cerr != nil {
		return refusedByPort(r, domain.ReasonConversionFailed, cerr)
	}
	curated, stats := conv.Document, conv.Stats
	// A standards SBOM comes back with no source digest: nothing was converted, so
	// there is no conversion to record. Every other road — including a curated
	// report's pass-through, which names no converter — records one.
	if conv.SourceDigest != "" {
		prov.ConvertedBy, prov.SourceDigest = conv.ConvertedBy, conv.SourceDigest
		_ = r.RecordConversion(conv.ConvertedBy, conv.SourceDigest, stats.FindingsTotal, stats.FindingsSkipped)
		_ = r.RecordComponentsSkipped(stats.ComponentsSkipped)
		_ = r.RecordComponentsUnmanaged(stats.ComponentsUnmanaged)
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
		has, ierr := s.hasInventory(ctx, res)
		if ierr != nil {
			// A precondition that could not be EVALUATED is not a precondition that
			// failed. Reporting `no_inventory_for_release` here would tell the
			// operator to upload an SBOM they have already uploaded.
			return failed(r, fmt.Sprintf("could not read the release's inventory: %v", ierr), ierr)
		}
		if !has {
			if !cmd.AllowWithoutSBOM {
				// Refused BEFORE the create, which is the whole reason the create is
				// late: a report for a brand-new version leaves no empty Release
				// behind. With B1's two requests this never bites — the SBOM request
				// creates the version and the report request finds it.
				return refused(r, domain.ReasonNoInventoryForRelease, noInventoryDetail(res))
			}
			prov.WithoutSBOM = true
		}
	}

	// 7. Find-or-create the version (B7's step 8), when resolution said it does not
	// exist yet. The first write of the request, and it is Registry's own idempotent
	// upsert, so two bots building the same version at the same moment get one row.
	releaseID := res.ReleaseID
	if res.ToCreate() {
		// `created` is Registry's answer about the ROW and there is nothing on a
		// receipt it answers — a receipt's `created` is about the EVIDENCE (D9) — so
		// it is discarded here deliberately.
		id, _, perr := s.provision.FindOrCreateRelease(ctx, res.ProjectID, res.Version)
		if perr != nil {
			return failed(r, fmt.Sprintf("could not create version %q: %v", res.Version, perr), perr)
		}
		releaseID = id
		_ = r.RecordRelease(releaseID)
	}

	// 8. File. The only step that writes EVIDENCE, and it writes the aggregate with
	// its outbox note in one transaction.
	_ = r.StartRegistering()
	filed, err := s.registrar.Register(ctx, RegisterCommand{
		Raw:              curated,
		Kind:             filedKind,
		Format:           conv.Format,
		SubjectReleaseID: releaseID,
		Provenance:       prov,
	})
	if err != nil {
		return failed(r, fmt.Sprintf("register: %v", err), err)
	}
	if ferr := r.Filed(string(filed.ID), filed.Created); ferr != nil {
		// The write reported success without naming a document. "Filed, pointing at
		// nothing" is the 2026-10-05 shape, so the receipt says `failed` instead of
		// claiming an id it does not have.
		return failed(r, ferr.Error(), ferr)
	}
	return r, nil
}

// hasInventory answers D6's precondition for whatever resolution landed on. For a
// version still to be created the answer is known WITHOUT a read: a release that does
// not exist yet has no inventory (B7's step 7 says so in one sentence), and there is
// no id to read one by — asking the store with an empty release id would be a question
// about every release and none.
func (s *IntakeService) hasInventory(ctx context.Context, res Resolution) (bool, error) {
	if res.ToCreate() {
		return false, nil
	}
	return s.inventory.HasInventory(ctx, res.ReleaseID)
}

// noInventoryDetail names what the caller has to do about D6, and the two cases need
// different sentences: a release that EXISTS is named by its id, which is what the
// operator looks it up by, while a version that does not exist yet has no id to name —
// telling them "release  has no inventory" is the shape that sends people hunting.
func noInventoryDetail(res Resolution) string {
	if res.ToCreate() {
		return fmt.Sprintf("version %q is not registered yet, so it has no inventory for a report to be recorded against; "+
			"upload the SBOM first — that request creates the version — or resend with allow_without_sbom=true", res.Version)
	}
	return fmt.Sprintf("release %s has no SBOM-derived inventory; upload the SBOM first, or resend with allow_without_sbom=true", res.ReleaseID)
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
