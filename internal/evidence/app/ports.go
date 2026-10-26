package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// TrustGate fingerprints and validates a raw artifact (implemented by adapters/trust).
type TrustGate interface {
	Admit(input TrustInput) (TrustOutcome, error)
}

// TrustInput is a raw artifact presented to the trust gate.
type TrustInput struct {
	Raw              []byte
	Kind             domain.Kind
	ExpectedChecksum string
	Provenance       domain.Provenance
}

// TrustOutcome is the trust gate's verdict.
type TrustOutcome struct {
	Fingerprint value.ContentFingerprint
	Status      domain.TrustStatus
	Provenance  domain.Provenance
	Reason      string
}

// Parser translates a raw SBOM of a supported standard into the canonical inventory
// (implemented by adapters/parser).
type Parser interface {
	Parse(ctx context.Context, format, specVersion string, raw []byte) (domain.Inventory, []string, error)
}

// SubjectRefValidator checks that a referenced Release exists. It is backed by the
// Shared Kernel registry (ReleaseExists); a stub stands in until that lands.
type SubjectRefValidator interface {
	ReleaseExists(ctx context.Context, releaseID string) (bool, error)
}

// Repository persists and reads Evidence aggregates (implemented by adapters/store).
type Repository interface {
	Save(ctx context.Context, e domain.Evidence, raw []byte, event domain.EvidenceRegistered) (id domain.EvidenceID, created bool, err error)
	GetByID(ctx context.Context, id domain.EvidenceID) (domain.Evidence, error)
	GetInventory(ctx context.Context, id domain.EvidenceID) (domain.Inventory, error)
	ListByRelease(ctx context.Context, releaseID string) ([]EvidenceSummary, error)
	// GetRawDocument returns a document's kind + raw stored bytes (the read path Knowledge
	// uses to parse an uploaded VEX — EDR-VEX-01 D1; Evidence serves, never parses).
	GetRawDocument(ctx context.Context, id domain.EvidenceID) (kind string, doc []byte, err error)
}

// EvidenceSummary is a list-view row for evidence filed against a release.
type EvidenceSummary struct {
	ID               domain.EvidenceID
	Kind             domain.Kind
	Fingerprint      string
	ProvenanceSource string
	FiledAt          time.Time
}

// IDGenerator assigns new opaque Evidence identities (implemented by an adapter
// using, e.g., a UUID source — the app itself stays free of that dependency).
type IDGenerator interface {
	NewID() domain.EvidenceID
}

// Clock supplies the current time (injectable for tests).
type Clock interface {
	Now() time.Time
}

// ProductAuthorizer answers ONE question for ONE request: may the caller act on this
// product? (EDR-INTAKE-01 B3, EDR-SECURITY-01 D4.)
//
// It is a function rather than a port because the answer belongs to a CREDENTIAL, and
// this ring never reads one: the edge that authenticated the request supplies the
// decision (`auth.Principal.AuthorizeProduct`), and the app only asks it at the step
// the order requires. That keeps `internal/platform/auth` out of the app ring while
// the authorization still happens where the resolved product is known.
//
// It travels ON the command, not on the context, so the slow path authorizes too: an
// overflowed intake is retried on a worker whose context is detached from the request,
// and a confinement that lived on the request context would silently widen to admin
// exactly when nobody is watching.
type ProductAuthorizer func(productID string) bool

// ResolveRequest is one release-resolution question: the two roads that can name a
// release, plus the caller's product authority so resolution can authorize at the
// step B7 puts it — between the product lookup and the project lookup.
type ResolveRequest struct {
	// Product, Project and Version name the release by its triple; ReleaseID names
	// it directly and wins.
	Product   string
	Project   string
	Version   string
	ReleaseID string
	// CreateRelease is the caller's `create_release=true` (B2). It changes what an
	// ABSENT version means and nothing else: resolution stays read-only and reports
	// the version as still to be created ([Resolution.ToCreate]) instead of refusing
	// it, while the find-or-create itself happens after every border check.
	CreateRelease bool
	// Authorize is the caller's product confinement, or NIL when there is none —
	// which is the posture of an `admin` key and of an auth-disabled node (B3). The
	// edge decides which of the two applies, because it is the only ring that may
	// read a credential; [ResolveRequest.Confined] is how resolution asks.
	Authorize ProductAuthorizer
}

// Confined reports whether the caller is restricted to particular products. When it
// is false the ownership reads are skipped entirely — an admin never pays for a
// lookup whose answer cannot change the outcome, and an auth-disabled node has no
// identity to confine.
func (r ResolveRequest) Confined() bool { return r.Authorize != nil }

// Resolution is what resolution ANSWERS (EDR-INTAKE-01 B7's step 4): which release
// this intake files against — or, when `create_release=true` named a version that is
// not registered yet under a Product and Project that are, the project that version
// is still TO BE CREATED under.
//
// The second case carries the project id and the version because the create at step 8
// must not look anything up again: re-resolving there would re-ask a question whose
// answer was already authorized, and the second answer could differ from the first.
type Resolution struct {
	// ReleaseID is the canonical release id, and it is EMPTY exactly when the version
	// is still to be created.
	ReleaseID string
	// ProjectID and Version name the version [ReleaseProvisioner] finds or creates at
	// step 8. They are set exactly when ReleaseID is empty.
	ProjectID string
	Version   string
}

// ToCreate reports whether resolution ended on a version that does not exist yet.
//
// It is DERIVED from the empty release id rather than carried as a second field, so
// the two cannot disagree: a resolution that both names a release and asks for one to
// be created is not a state this type can hold.
func (r Resolution) ToCreate() bool { return r.ReleaseID == "" }

// ReleaseResolver resolves the release an intake names — either directly by
// `release_id`, or by the {product, project, version} triple (EDR-INTAKE-01 D7).
//
// It is READ-ONLY, and that is the decision, not an implementation detail: resolution
// creates nothing, and that is what keeps every border refusal free of a side effect.
// With `create_release=true` an absent version is an ANSWER rather than a refusal —
// [Resolution.ToCreate] — and the create itself is a separate port called at step 8,
// after every border check (B2, B7).
//
// A Product or Project that does not resolve is still a refusal, never a creation:
// those names are human-owned and a typo in one is where a parallel estate comes from,
// which is the hazard D7 refused `create_if_missing` over.
//
// An unresolvable release is reported with [domain.Reject] carrying
// [domain.ReasonUnknownRelease] and a detail naming which of the three was not found.
// A caller refused for authorization is reported with [domain.ReasonUnauthorized] and
// a detail that is the SAME for every outcome a product-scoped key must not
// distinguish (B3) — stating the rule, never the estate.
type ReleaseResolver interface {
	Resolve(ctx context.Context, req ResolveRequest) (Resolution, error)
}

// ReleaseProvisioner is the ONE write Evidence makes into Registry (EDR-INTAKE-01 B2),
// and the interface's SHAPE is the bound rather than a comment asking for restraint:
// it can create a version under a project that already exists, and there is no product
// or project verb to reach for. D7's wall — "a write from Evidence into Registry is
// neither an event nor a read" — is narrowed, not removed, and a future widening is a
// visible interface change instead of a new argument.
//
// Registry still owns what "one Release" means: the uniqueness rule, the id and the
// `created` answer come from its own idempotent upsert, so two bots building the same
// version at the same moment get one row (B4).
//
// It is called at step 8 of the order and nowhere else — after every border check,
// immediately before filing — so a submission refused for `schema_invalid`,
// `empty_report`, `no_inventory_for_release` or any other border reason creates
// NOTHING. `409 duplicate_other_release` is the one refusal that can follow a create,
// because the database discovers it at the evidence insert; the created version is
// retained (a legitimate Release with no evidence yet) and a corrected retry reuses it.
//
// `created` is Registry's answer about the ROW, and intake has nothing to say with it:
// a receipt's `created` is about the EVIDENCE (D9). It is in the signature because
// find-or-create states it, and the app discards it deliberately rather than by
// oversight.
type ReleaseProvisioner interface {
	FindOrCreateRelease(ctx context.Context, projectID, version string) (id string, created bool, err error)
}

// InventoryReader answers D6's precondition: does an Evidence document of
// `kind=sbom` exist whose subject release is this one?
//
// It is a single boolean because Evidence's own inventory has exactly two states.
// `Register` parses inline and `Save` writes the row and its canonical inventory in
// ONE transaction, and the domain refuses an SBOM that parsed to zero components —
// so "uploaded but not parsed" and "parsed but empty" do not exist here, and the
// five states a reviewer might distinguish collapse to two. The check is
// release-scoped by construction, so another release's inventory can never satisfy it.
type InventoryReader interface {
	HasInventory(ctx context.Context, releaseID string) (bool, error)
}

// ReportStats counts what a conversion saw: FindingsTotal source records considered,
// FindingsSkipped of them refused by the converter's row-level skip rule. Both are
// carried, never just the kept count — "427 of 427" and "427 of 500" must not look
// alike, which is the whole of the silent-skip class (KN-SCAN-OBS-1).
//
// ComponentsSkipped is the same rule for an inventory conversion (EDR-INTAKE-01,
// 2026-10-26 P4): the package lines a converted SBOM left out for want of an identity.
type ReportStats struct {
	FindingsTotal     int
	FindingsSkipped   int
	ComponentsSkipped int
}

// Conversion is what [ReportRegistry.Convert] hands back: the document to file, the
// format it is in, and the provenance of the conversion.
//
// SourceDigest (and ConvertedBy) are empty when the submitted bytes ARE the document —
// a CycloneDX or SPDX SBOM, which is identified and never re-serialized, because that
// would change the fingerprint that dedups a re-upload. A curated report passes
// through too, but carries a digest and its counts: its source is then also the
// document, and only ConvertedBy is empty. Format is what Evidence's parser is told the
// document is; for a converted SBOM it is the standards format the converter wrote,
// not the dialect that arrived.
type Conversion struct {
	Document     []byte
	Format       string
	Stats        ReportStats
	ConvertedBy  string
	SourceDigest string
}

// ReportRegistry is the converter ACL as the app ring sees it (EDR-INTAKE-01
// D4/D5): identification and conversion of a submitted vendor dialect into the one
// document Themis files. It is implemented by `adapters/report`, which the app must
// not import — a vendor shape never reaches these rings, and neither does the package
// that understands one.
//
// Kind and dialect cross as plain strings for the same reason: they are the ACL's
// vocabulary (`sbom` / `vuln-report`, `spdx` / `cortex-csv` / …) echoed back to the
// client as `detected_kind` and `detected_format`, not Evidence's own kinds.
// [IntakeService] maps the former onto the latter and refuses a kind it cannot place.
//
// Both methods report a refusal with [domain.Reject], so the closed taxonomy is the
// only vocabulary that crosses the boundary. An error carrying no reason is an
// infrastructure fault, and the caller must not invent a reason for it.
type ReportRegistry interface {
	// Detect names the body: D5a's closed, ordered table, first match wins.
	// Identification is not admission — a named body has only earned the right to be
	// validated against its dialect's rules.
	//
	// declaredKind is the caller's `kind` (empty when none was declared). One that
	// agrees changes nothing, one the body cannot be is `declared_format_mismatch`, and
	// on the one dialect that is both kinds — a Nessus export — it chooses which of
	// the two is read (2026-10-26 P1).
	Detect(contentType string, body []byte, declaredKind string) (kind, dialect string, err error)

	// Convert produces the document to file plus the provenance of the conversion:
	// which converter version produced it, and the digest of the bytes that arrived
	// (which, for a converted submission, are not the bytes filed). A standards SBOM
	// passes through unchanged.
	//
	// It is pure in (body, suppliedObservedAt) — no clock. A supplied timestamp is
	// the caller's assertion about WHICH observation this is and wins over
	// derivation; with neither available the refusal is `observed_at_underivable`,
	// never the upload time (D3).
	Convert(kind, dialect string, body []byte, suppliedObservedAt time.Time) (Conversion, error)
}

// EvidenceRegistrar is the one write intake performs, and it is deliberately the
// EXISTING Register use case rather than a second writer: the trust gate,
// fingerprinting, the aggregate's invariants and the outbox note in one transaction
// are what "filed" means, and a parallel path into the store would be a second
// definition of it. Satisfied by *EvidenceService as-is.
type EvidenceRegistrar interface {
	Register(ctx context.Context, cmd RegisterCommand) (RegisterResult, error)
}
