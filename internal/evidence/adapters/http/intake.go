package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/evidence/adapters/http/gen"
	"github.com/themis-project/themis/internal/evidence/adapters/report"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/observability"
)

// The intake door's defaults (EDR-INTAKE-01 D9/D13).
const (
	// DefaultInlineBudget is how long the door tries to finish the work before
	// handing the client a `202` and a receipt to come back to.
	DefaultInlineBudget = 5 * time.Second
	// DefaultReceiptTTL is how long a receipt is retained. Receipts are
	// operational records of an attempt, including a refused one — not evidence.
	DefaultReceiptTTL = 30 * 24 * time.Hour
	// DefaultMaxBytes is D13's body bound.
	DefaultMaxBytes int64 = 64 << 20
	// retryAfterSeconds is what both the `202` and the backlog-full `503` tell the
	// client to wait. One constant because they mean the same thing to a client:
	// come back shortly.
	retryAfterSeconds = 2
	// recoveryDetail is what a receipt a restart interrupted says. It names the
	// action, because "failed" with no instruction leaves the operator guessing
	// whether the document landed.
	recoveryDetail = "interrupted by restart; resubmit"
)

// IntakeRunner is the intake use case as this edge needs it. Satisfied by
// *app.IntakeService.
type IntakeRunner interface {
	Intake(ctx context.Context, cmd app.IntakeCommand) (*domain.Receipt, error)
}

// ReceiptStore persists intake receipts (satisfied by *store.Store).
type ReceiptStore interface {
	SaveIntakeReceipt(ctx context.Context, r store.IntakeReceipt) error
	LoadIntakeReceipt(ctx context.Context, intakeID string) (store.IntakeReceipt, error)
	FindIntakeReceiptByIdempotencyKey(ctx context.Context, key string) (store.IntakeReceipt, error)
	FailStaleNonTerminalReceipts(ctx context.Context, olderThan time.Time, detail string) (int, error)
}

// InventoryCounter reads a filed document's canonical inventory, so a receipt for an
// SBOM can report how many components it actually carries. Satisfied by
// *app.EvidenceService.
//
// It is a read AFTER filing rather than a count threaded out of the write path:
// `Register` already owns the parse and the transaction, and widening its result to
// carry a number the write does not need would put a reporting concern inside the
// one step that must stay about filing.
type InventoryCounter interface {
	GetInventory(ctx context.Context, id domain.EvidenceID) (domain.Inventory, error)
}

// IntakeConfig is the door's operational configuration. Every zero value takes the
// documented default rather than meaning "off" or "unlimited" — a bound switched off
// by accident is indistinguishable downstream from no bound at all.
type IntakeConfig struct {
	// MaxBytes is D13's request-body bound, applied before the body is buffered.
	MaxBytes int64
	// InlineBudget is how long the door works before answering `202` (D9).
	InlineBudget time.Duration
	// KnowledgeURL and GovernanceURL build a terminal receipt's `next_checks`
	// (D10). Empty means the field is OMITTED — never a broken URL.
	KnowledgeURL  string
	GovernanceURL string
}

func (c IntakeConfig) withDefaults() IntakeConfig {
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultMaxBytes
	}
	if c.InlineBudget <= 0 {
		c.InlineBudget = DefaultInlineBudget
	}
	return c
}

// Intake serves the single intake door (EDR-INTAKE-01 D1): `POST /api/v1/intake` and
// the receipt it is always addressable by.
//
// The edge owns the receipt rather than the use case, and that split is deliberate.
// `app.IntakeService` decides what happens to a document; the receipt is the record
// that SOMEONE TRIED, which has to survive the attempt being abandoned — a refusal,
// a restart, a client that hung up. Those are all facts about a request, so they are
// recorded where requests are handled.
type Intake struct {
	run      IntakeRunner
	receipts ReceiptStore
	inv      InventoryCounter
	cfg      IntakeConfig
	worker   *intakeWorker
	log      *observability.Logger
	newID    func() string
}

// NewIntake wires the intake door and starts its bounded overflow worker. A nil
// logger is the no-op logger.
func NewIntake(run IntakeRunner, receipts ReceiptStore, inv InventoryCounter, cfg IntakeConfig, log *observability.Logger) *Intake {
	if log == nil {
		log = observability.Nop()
	}
	i := &Intake{
		run:      run,
		receipts: receipts,
		inv:      inv,
		cfg:      cfg.withDefaults(),
		log:      log,
		newID:    uuid.NewString,
	}
	i.worker = startIntakeWorker(i.process)
	return i
}

// Close stops the overflow worker. In-flight work finishes first.
func (i *Intake) Close() {
	if i != nil {
		i.worker.close()
	}
}

// RecoverInterruptedReceipts closes out the receipts a previous process left
// non-terminal, and returns how many. Call it at startup, before serving.
//
// A receipt advances in the process doing the work, so a process that died
// mid-intake leaves one stuck at `accepted` — and a client polling `status_url`
// would wait forever on a goroutine that no longer exists. Only receipts older than
// the inline budget are touched: anything younger could still be in flight.
func (i *Intake) RecoverInterruptedReceipts(ctx context.Context) (int, error) {
	cutoff := time.Now().UTC().Add(-i.cfg.InlineBudget)
	return i.receipts.FailStaleNonTerminalReceipts(ctx, cutoff, recoveryDetail)
}

// SubmitIntake handles POST /intake — the one door. The body IS the artifact and the
// metadata is query parameters (see the change's design, "Why the body is raw").
func (h *Handler) SubmitIntake(w http.ResponseWriter, r *http.Request, params gen.SubmitIntakeParams) {
	if h.intake == nil {
		writeProblem(w, http.StatusServiceUnavailable, "intake is not configured",
			"this node has no intake door wired; use POST /evidence", nil)
		return
	}
	h.intake.submit(w, r, params)
}

// GetIntakeReceipt handles GET /intake/{intakeId} — every intake is addressable,
// including a refused one (D9).
func (h *Handler) GetIntakeReceipt(w http.ResponseWriter, r *http.Request, intakeID string) {
	if h.intake == nil {
		writeProblem(w, http.StatusServiceUnavailable, "intake is not configured",
			"this node has no intake door wired", nil)
		return
	}
	h.intake.read(w, r, intakeID)
}

func (i *Intake) read(w http.ResponseWriter, r *http.Request, intakeID string) {
	rec, err := i.receipts.LoadIntakeReceipt(r.Context(), intakeID)
	if err != nil {
		writeReadError(w, err)
		return
	}
	// Always 200: the receipt is the answer, whatever it says. Rendering a rejected
	// receipt as its own refusal status would make "the attempt was refused" and
	// "this read was refused" the same response.
	writeJSON(w, http.StatusOK, i.view(rec, false, 0))
}

func (i *Intake) submit(w http.ResponseWriter, r *http.Request, params gen.SubmitIntakeParams) {
	key := strval(params.IdempotencyKey)
	rec := store.IntakeReceipt{
		IntakeID:       i.newID(),
		IdempotencyKey: key,
		Status:         domain.ReceiptAccepted,
	}

	// A receipt write must not ride the request's cancellation: the whole point of a
	// receipt is that it survives the attempt, including a client that hung up.
	bg := context.WithoutCancel(r.Context())

	// D12, before any work: the same key returns the ORIGINAL receipt. Checked first
	// so a retry costs nothing and, more importantly, files nothing.
	if key != "" {
		if prev, err := i.receipts.FindIntakeReceiptByIdempotencyKey(r.Context(), key); err == nil {
			i.respond(w, prev, false, 0)
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			i.fail(w, rec, fmt.Sprintf("could not read the idempotency key's receipt: %v", err))
			return
		}
	}

	// The command's parameter half is assembled BEFORE the body, because B7's step 1
	// is parameter validation and it comes before the size bound: the checks need no
	// body and have no side effect, so a request that is both oversized and carries a
	// malformed `build_id` is told about the `build_id` — the fault the caller can
	// act on. Only a request using the new parameters can take that branch, so no
	// existing answer moves.
	cmd := app.IntakeCommand{
		Product:               strval(params.Product),
		Project:               strval(params.Project),
		Version:               strval(params.Version),
		ReleaseID:             strval(params.ReleaseId),
		CreateRelease:         params.CreateRelease != nil && *params.CreateRelease,
		BuildID:               strval(params.BuildId),
		AllowWithoutSBOM:      params.AllowWithoutSbom != nil && *params.AllowWithoutSbom,
		ProvenanceSource:      strval(params.ProvenanceSource),
		ProvenanceImageDigest: strval(params.ProvenanceImageDigest),
		// The caller's product confinement, read from the authenticated principal
		// here — the only ring that may read a credential — and carried on the
		// command so the overflow worker's detached context authorizes identically.
		Authorize: productAuthorizer(r),
	}
	if refusal := cmd.ParameterRefusal(); refusal != nil {
		i.reject(w, bg, rec, refusal.Reason, refusal.Detail)
		return
	}

	// D13's bound, checked BEFORE the body is buffered — a limit applied after the
	// read protects nothing it was meant to.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, i.cfg.MaxBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			i.reject(w, bg, rec, domain.ReasonPayloadTooLarge,
				fmt.Sprintf("the request body is over the %d-byte intake limit", i.cfg.MaxBytes))
			return
		}
		i.reject(w, bg, rec, domain.ReasonMalformedBody,
			fmt.Sprintf("the request body could not be read: %v", err))
		return
	}

	// `expected_checksum` is verified HERE, over the SUBMITTED bytes, and that is the
	// only place it can be right: for a converted submission the filed bytes are not
	// the bytes the caller hashed (D2), so a gate downstream of the converter would
	// compare the assertion against a different document.
	if want := strval(params.ExpectedChecksum); want != "" {
		got := value.NewContentFingerprint(body).String()
		if strings.ToLower(strings.TrimSpace(want)) != got {
			rec.SourceDigest = got
			i.reject(w, bg, rec, domain.ReasonChecksumMismatch,
				fmt.Sprintf("expected_checksum %s does not match the submitted bytes, whose SHA-256 is %s", want, got))
			return
		}
	}

	observedAt, err := parseObservedAt(strval(params.ObservedAt))
	if err != nil {
		i.reject(w, bg, rec, domain.ReasonObservedAtInvalid, err.Error())
		return
	}

	cmd.ContentType = r.Header.Get("Content-Type")
	cmd.Body = body
	cmd.ObservedAt = observedAt

	ctx, cancel := context.WithTimeout(r.Context(), i.cfg.InlineBudget)
	defer cancel()
	receipt, runErr := i.run.Intake(ctx, cmd)
	if receipt == nil {
		// The use case's contract is that every outcome is ON the receipt, so this
		// is a defect behind the port rather than anything the document did. Guarded
		// because the alternative is a nil dereference that takes the node down.
		i.fail(w, rec, fmt.Sprintf("the intake use case returned no receipt: %v", runErr))
		return
	}

	// The budget ran out and the work did not land. Only `filed` is trusted here:
	// under an expired deadline every other outcome may be the CLOCK talking rather
	// than the document — a cancelled read reports as an unresolvable release, and a
	// caller-side timeout read as a verdict is a defect this estate has already paid
	// for (AI-TIMEOUT-1). So anything short of filed is retried from the start on the
	// overflow worker, which is safe because re-filing the same content dedups (D8).
	if overBudget(ctx) && receipt.Status() != domain.ReceiptFiled {
		// The backlog is checked BEFORE the receipt is written: a `503` means
		// nothing was accepted, nothing was filed and there is no receipt to find,
		// so the whole request is safe to retry verbatim.
		if !i.worker.enqueue(intakeJob{receipt: rec, cmd: cmd}) {
			w.Header().Set("Retry-After", fmt.Sprint(retryAfterSeconds))
			writeProblem(w, http.StatusServiceUnavailable, "intake backlog is full",
				"no work was accepted and nothing was filed; retry this request after the Retry-After interval", nil)
			return
		}
		saved, err := i.persist(bg, rec)
		if err != nil {
			i.fail(w, rec, fmt.Sprintf("could not record the receipt: %v", err))
			return
		}
		i.respond(w, saved, false, retryAfterSeconds)
		return
	}

	if runErr != nil {
		i.log.Error("intake failed", observability.String("intake_id", rec.IntakeID), observability.Err(runErr))
	}
	rec = i.merge(bg, rec, receipt, runErr)
	// B3's non-disclosing refusal, rendered apart from every other refusal because
	// the property it has to hold is a property of the BYTES — see refuseUnauthorized.
	if rec.Status == domain.ReceiptRejected && rec.Reason == domain.ReasonUnauthorized {
		i.refuseUnauthorized(w, bg, r, rec)
		return
	}
	saved, err := i.persist(bg, rec)
	if err != nil {
		i.fail(w, rec, fmt.Sprintf("could not record the receipt: %v", err))
		return
	}
	i.respond(w, saved, receipt.Created(), 0)
}

// merge copies a finished attempt's outcome onto the receipt row, names the filing
// step's typed refusals, and reads back the component count for a filed SBOM so the
// receipt reports what actually landed.
func (i *Intake) merge(ctx context.Context, rec store.IntakeReceipt, rc *domain.Receipt, cause error) store.IntakeReceipt {
	rec.Status = rc.Status()
	rec.Reason = rc.Reason()
	rec.Detail = rc.Detail()
	// The filing step reports its refusals as typed ERRORS, because they arrive from
	// the write, and the use case therefore records them as a failure of Themis. Two
	// of them are statements about the DOCUMENT and have a name in the closed
	// taxonomy, so the border gives them that name — the same translation the old
	// door's `writeRegisterError` performs. Without it a cross-release duplicate,
	// which D8 requires to stay the loud 409 it has always been, would read as a
	// server fault.
	if rc.Status() == domain.ReceiptFailed && cause != nil {
		if reason, ok := refusalFromFiling(cause); ok {
			rec.Status, rec.Reason, rec.Detail = domain.ReceiptRejected, reason, cause.Error()
		}
	}
	rec.EvidenceID = rc.EvidenceID()
	rec.ReleaseID = rc.ReleaseID()
	rec.DetectedKind = rc.DetectedKind()
	rec.DetectedFormat = rc.DetectedFormat()
	rec.FindingsTotal = rc.FindingsTotal()
	rec.FindingsSkipped = rc.FindingsSkipped()
	rec.ConvertedBy = rc.ConvertedBy()
	if rc.SourceDigest() != "" {
		rec.SourceDigest = rc.SourceDigest()
	}
	if rc.Status() == domain.ReceiptFiled && rc.DetectedKind() == string(report.KindSBOM) && i.inv != nil {
		if inv, err := i.inv.GetInventory(ctx, domain.EvidenceID(rc.EvidenceID())); err == nil {
			rec.Components = len(inv.Components())
		} else {
			// The document is filed; a count we could not read is a gap in the
			// receipt, never a reason to call the filing anything but filed.
			i.log.Warn("intake filed but the inventory count could not be read",
				observability.String("intake_id", rec.IntakeID), observability.Err(err))
		}
	}
	return rec
}

// refusalFromFiling names the filing step's typed refusals in the closed taxonomy.
//
// It is deliberately a SHORT, closed list and not a catch-all: everything else that
// comes back from a write is a statement about Themis, and giving it a reason would
// send the operator to fix a document that was never the problem.
//
// `ErrRejected` maps to `schema_invalid` because what remains in the trust gate after
// the intake's own checks IS structural — well-formed JSON and the curated shape — so
// a rejection there means the border and the gate disagree about the document, not
// that the server broke. `ErrUnknownSubject` maps to `unknown_release` for the window
// where the release resolved and then vanished before the write.
func refusalFromFiling(err error) (domain.RejectReason, bool) {
	var filedElsewhere *app.ContentFiledElsewhereError
	switch {
	case errors.As(err, &filedElsewhere):
		return domain.ReasonDuplicateOtherRelease, true
	case errors.Is(err, app.ErrUnknownSubject):
		return domain.ReasonUnknownRelease, true
	case errors.Is(err, app.ErrRejected):
		return domain.ReasonSchemaInvalid, true
	default:
		return "", false
	}
}

// persist writes the receipt, and when the asserted key already owns one returns
// THAT receipt instead. A collision on the key is a retry arriving, which is the
// thing the key exists to make safe — not a persistence failure.
func (i *Intake) persist(ctx context.Context, rec store.IntakeReceipt) (store.IntakeReceipt, error) {
	err := i.receipts.SaveIntakeReceipt(ctx, rec)
	if errors.Is(err, store.ErrIdempotencyKeyTaken) {
		return i.receipts.FindIntakeReceiptByIdempotencyKey(ctx, rec.IdempotencyKey)
	}
	return rec, err
}

// reject records a refusal by name and renders it. A refusal is a complete, truthful
// outcome — the document was read, understood and declined — so it leaves a receipt
// and nothing else: no evidence, no event, no bus traffic (D13).
func (i *Intake) reject(w http.ResponseWriter, ctx context.Context, rec store.IntakeReceipt, reason domain.RejectReason, detail string) {
	rec.Status, rec.Reason, rec.Detail = domain.ReceiptRejected, reason, detail
	saved, err := i.persist(ctx, rec)
	if err != nil {
		i.fail(w, rec, fmt.Sprintf("could not record the refusal: %v", err))
		return
	}
	i.respond(w, saved, false, 0)
}

// refuseUnauthorized renders the ONE refusal whose contract is about its bytes
// (EDR-INTAKE-01 B3, status-code rows 8-10 and 17-18): for a `product:<id>` key,
// every outcome that is not "resolves to exactly my own product" — someone else's
// product, no such product, an ambiguous name, another product's release id, a
// release id that does not exist — must be INDISTINGUISHABLE. Otherwise intake is a
// product-name and release-id oracle for any holder of any product key.
//
// Two things follow, and both are easy to lose:
//
//   - The detail is the resolver's single constant, so there is no second wording to
//     drift (the three refusals are written once, not three times).
//   - The response names NO receipt. A fresh `intake_id` per request would make the
//     bodies differ on exactly the field a caller can replay against, so the
//     byte-equality property could not hold at all. The attempt is still RECORDED —
//     D9's rule that every intake is addressable is unchanged, and an operator
//     querying receipts sees the refused attempts — it is the WIRE that says nothing.
//     The authentication middleware's own `403` (row 2) has the same shape, which is
//     the point: the two refusals on this door are the same class of answer, a
//     statement about the key rather than about the document.
//
// The log carries what the response does not (R1): the operator debugging a `403`
// needs the key id and the receipt, and the log is where strictly more can be said.
func (i *Intake) refuseUnauthorized(w http.ResponseWriter, ctx context.Context, r *http.Request, rec store.IntakeReceipt) {
	var keyID string
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		keyID = p.KeyID
	}
	i.log.Warn("intake refused: the key is not authorized for the product this request names",
		observability.String("intake_id", rec.IntakeID),
		observability.String("key_id", keyID))
	if _, err := i.persist(ctx, rec); err != nil {
		i.fail(w, rec, fmt.Sprintf("could not record the refusal: %v", err))
		return
	}
	writeJSON(w, http.StatusForbidden, gen.IntakeProblem{
		Title:  "intake refused",
		Status: http.StatusForbidden,
		Reason: reasonPtr(domain.ReasonUnauthorized),
		Detail: rec.Detail,
	})
}

// productAuthorizer reads the caller's product confinement off the authenticated
// principal, and returns NIL when none applies: an `admin` key authorizes every
// product, and an auth-disabled node (`THEMIS_AUTH_DATABASE_DSN` unset) has no
// principal at all and is treated as admin — the same posture every other route on
// that node already has, and the reason `THEMIS_AUTH_REQUIRED=1` exists (B3).
//
// Anything else — a `product:<id>` key, and any key that reached this door without a
// write-capable scope — gets its own `AuthorizeProduct`, which is false for every
// product but its own. That is fail-closed by construction: the only way to be
// unconfined is to be admin or to be on a node with no identity at all.
func productAuthorizer(r *http.Request) app.ProductAuthorizer {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsAdmin() {
		return nil
	}
	return p.AuthorizeProduct
}

// fail reports that Themis could not carry the attempt out — a statement about
// Themis, not about the document, which is why it carries no reason. Nothing is
// persisted: the write is the thing that just failed.
func (i *Intake) fail(w http.ResponseWriter, rec store.IntakeReceipt, detail string) {
	i.log.Error("intake could not be recorded",
		observability.String("intake_id", rec.IntakeID), observability.String("detail", detail))
	writeJSON(w, http.StatusInternalServerError, gen.IntakeProblem{
		Title:    "intake failed",
		Status:   http.StatusInternalServerError,
		Detail:   detail,
		IntakeId: strptr(rec.IntakeID),
	})
}

// respond renders one receipt: a refusal as a Problem naming its reason, anything
// else as the receipt itself.
func (i *Intake) respond(w http.ResponseWriter, rec store.IntakeReceipt, created bool, retryAfter int) {
	code := receiptStatusCode(rec, created)
	switch rec.Status {
	case domain.ReceiptRejected:
		writeJSON(w, code, gen.IntakeProblem{
			Title:    "intake refused",
			Status:   code,
			Reason:   reasonPtr(rec.Reason),
			Detail:   rec.Detail,
			IntakeId: strptr(rec.IntakeID),
		})
	case domain.ReceiptFailed:
		writeJSON(w, code, gen.IntakeProblem{
			Title:    "intake failed",
			Status:   code,
			Detail:   rec.Detail,
			IntakeId: strptr(rec.IntakeID),
		})
	default:
		out := i.view(rec, created, retryAfter)
		// A POST that filed nothing new (a D8 dedup, or an Idempotency-Key replay) says
		// created=false out loud. Omitting it reads the same as "not reported", and the
		// contract (EDR-INTAKE-01 D12) promises the explicit false. A GET leaves it out:
		// whether the original request created the document is not stored on the receipt.
		if rec.Status == domain.ReceiptFiled && out.Created == nil {
			out.Created = &created
		}
		writeJSON(w, code, out)
	}
}

// view renders a receipt on the wire.
func (i *Intake) view(rec store.IntakeReceipt, created bool, retryAfter int) gen.IntakeReceipt {
	out := gen.IntakeReceipt{
		IntakeId:        rec.IntakeID,
		Status:          gen.ReceiptStatus(rec.Status),
		StatusUrl:       "/api/v1/intake/" + rec.IntakeID,
		Detail:          strptr(rec.Detail),
		ReleaseId:       strptr(rec.ReleaseID),
		DetectedKind:    strptr(rec.DetectedKind),
		DetectedFormat:  strptr(rec.DetectedFormat),
		FindingsTotal:   intptr(rec.FindingsTotal),
		FindingsSkipped: intptr(rec.FindingsSkipped),
		Components:      intptr(rec.Components),
		SourceDigest:    strptr(rec.SourceDigest),
		ConvertedBy:     strptr(rec.ConvertedBy),
		BuildId:         strptr(rec.BuildID),
		CreatedAt:       timeptr(rec.CreatedAt),
		UpdatedAt:       timeptr(rec.UpdatedAt),
	}
	if rec.Reason != "" {
		out.Reason = reasonPtr(rec.Reason)
	}
	if rec.EvidenceID != "" {
		out.EvidenceId = strptr(rec.EvidenceID)
	}
	if created {
		out.Created = &created
	}
	if retryAfter > 0 {
		out.RetryAfterSeconds = intptr(retryAfter)
	}
	if checks := i.nextChecks(rec); len(checks) > 0 {
		out.NextChecks = &checks
	}
	return out
}

// nextChecks names who answers "did the work land" (D10). The receipt is terminal at
// `filed` and does NOT claim correlation is complete: Knowledge owns correlation, and
// having Evidence poll it would invent the coupling the bus exists to avoid.
//
// An unset base URL means the field is OMITTED. A client can tell "nobody told me
// where to look" from a URL that 404s; it cannot tell a broken URL from a broken
// pipeline.
func (i *Intake) nextChecks(rec store.IntakeReceipt) []gen.NextCheck {
	if rec.Status != domain.ReceiptFiled {
		return nil
	}
	var out []gen.NextCheck
	if i.cfg.KnowledgeURL != "" && rec.DetectedKind == string(report.KindReport) && rec.EvidenceID != "" {
		out = append(out, gen.NextCheck{
			What: "unresolved",
			Url:  strings.TrimRight(i.cfg.KnowledgeURL, "/") + "/api/v1/scanner-reports/" + rec.EvidenceID + "/unresolved",
		})
	}
	if i.cfg.GovernanceURL != "" && rec.ReleaseID != "" {
		out = append(out, gen.NextCheck{
			What: "posture",
			Url:  strings.TrimRight(i.cfg.GovernanceURL, "/") + "/api/v1/releases/" + rec.ReleaseID + "/posture",
		})
	}
	return out
}

// --- the reason -> HTTP status table (D11) ---------------------------------

// httpStatusFor is EDR-INTAKE-01 D11's table, and it is a table because the mapping
// IS the contract: a consumer switches on `reason` and reads the status, and the two
// disagreeing is how a refusal becomes a mystery. `TestReasonToHTTPStatusCoversTheTaxonomy`
// walks domain.AllRejectReasons() against it, so a reason added without a status
// fails the build rather than quietly becoming a 422.
var httpStatusFor = map[domain.RejectReason]int{
	domain.ReasonUnknownRelease:         http.StatusNotFound,
	domain.ReasonNoInventoryForRelease:  http.StatusConflict,
	domain.ReasonUnrecognisedFormat:     http.StatusUnsupportedMediaType,
	domain.ReasonDeclaredFormatMismatch: http.StatusBadRequest,
	domain.ReasonMalformedBody:          http.StatusBadRequest,
	domain.ReasonSourceInvalid:          http.StatusUnprocessableEntity,
	domain.ReasonSchemaInvalid:          http.StatusUnprocessableEntity,
	domain.ReasonEmptyReport:            http.StatusUnprocessableEntity,
	domain.ReasonObservedAtUnderivable:  http.StatusUnprocessableEntity,
	domain.ReasonObservedAtInvalid:      http.StatusUnprocessableEntity,
	domain.ReasonConversionFailed:       http.StatusUnprocessableEntity,
	domain.ReasonChecksumMismatch:       http.StatusUnprocessableEntity,
	domain.ReasonDuplicateOtherRelease:  http.StatusConflict,
	domain.ReasonPayloadTooLarge:        http.StatusRequestEntityTooLarge,
	domain.ReasonTooManyRecords:         http.StatusRequestEntityTooLarge,
	// 403, not 401: an UNAUTHENTICATED request never reaches this handler — the
	// middleware answers a missing or invalid key with its own `401` and no reason
	// at all (B7 row 1). What reaches here is a valid key that may not act on the
	// product this request names (rows 8-10, 17-18), which is an authorization
	// refusal. Nothing produced this reason before the 2026-10-12 amendment, so no
	// existing response moves; see refuseUnauthorized for the bytes it renders.
	domain.ReasonUnauthorized: http.StatusForbidden,
	// The 2026-10-12 amendment's four (its status-code table). The three parameter
	// faults are malformed REQUESTS — the caller named the release two ways, named
	// it partially, or sent a `build_id` outside the bound — so they are 400, not
	// the 422 of a document that was read and declined. `ambiguous_name` is 422
	// because the request is well-formed and it is the ESTATE that cannot answer it.
	domain.ReasonCreateReleaseConflict:   http.StatusBadRequest,
	domain.ReasonIncompleteReleaseTriple: http.StatusBadRequest,
	domain.ReasonAmbiguousName:           http.StatusUnprocessableEntity,
	domain.ReasonBuildIDInvalid:          http.StatusBadRequest,
}

func statusForReason(reason domain.RejectReason) int {
	if code, ok := httpStatusFor[reason]; ok {
		return code
	}
	// Unreachable through the domain, which refuses a reason outside the closed
	// taxonomy. 422 rather than 500: the document was understood and declined, and
	// an unmapped reason is a contract gap on our side, not a server fault.
	return http.StatusUnprocessableEntity
}

// receiptStatusCode is the one place a receipt becomes a status code, so the POST
// response and an Idempotency-Key replay cannot drift apart.
//
// A filed receipt is `201` only when THIS request created the document. A replay and
// a read both pass created=false and get `200`, which is the honest answer: the
// receipt already existed and this request created nothing.
func receiptStatusCode(rec store.IntakeReceipt, created bool) int {
	switch rec.Status {
	case domain.ReceiptFiled:
		if created {
			return http.StatusCreated
		}
		return http.StatusOK
	case domain.ReceiptRejected:
		return statusForReason(rec.Reason)
	case domain.ReceiptFailed:
		return http.StatusInternalServerError
	default:
		return http.StatusAccepted
	}
}

// overBudget reports whether the inline attempt ran out of time or was abandoned.
//
// The CLOCK is consulted as well as the context because they are the same fact and
// only one of them is observable without waiting: a context publishes its deadline
// error from a timer goroutine, so at a very short budget — which is how a test and a
// deliberately tiny configuration force the overflow path — the deadline can have
// passed while `ctx.Err()` is still nil. Reading the clock makes the decision
// deterministic instead of nearly always right.
func overBudget(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

// parseObservedAt reads the caller's assertion about WHICH observation this is (D3).
//
// Empty means derive it from the submitted data. A value that is present but
// unparseable or implausible is `observed_at_invalid` and never a silent fallback to
// `now`: a report stamped fresh and re-uploaded tomorrow is a second scan of the same
// image, and no operator can tell it from a real one.
func parseObservedAt(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("observed_at %q is not an RFC 3339 timestamp", raw)
	}
	t = t.UTC()
	if t.Year() < 2000 {
		return time.Time{}, fmt.Errorf("observed_at %s is implausible: no scan predates 2000", raw)
	}
	if t.After(time.Now().UTC().Add(24 * time.Hour)) {
		return time.Time{}, fmt.Errorf("observed_at %s is implausible: more than 24h in the future", raw)
	}
	return t, nil
}

func reasonPtr(r domain.RejectReason) *gen.RejectReason {
	v := gen.RejectReason(r)
	return &v
}

func intptr(i int) *int { return &i }

func timeptr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
