package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	evhttp "github.com/themis-project/themis/internal/evidence/adapters/http"
	"github.com/themis-project/themis/internal/evidence/adapters/http/gen"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/observability"
)

// --- fakes ------------------------------------------------------------------

// fakeRunner stands in for the intake use case. `build` shapes the receipt it
// returns; `block` lets a test hold the overflow worker still so the backlog can
// actually fill.
type fakeRunner struct {
	build func(cmd app.IntakeCommand) *domain.Receipt
	// inlineBuild, when set, answers the INLINE attempt instead of build — which is
	// how a test says "the budget ran out before anything landed" and lets build
	// answer the worker's retry. A nil builder returns NO receipt, which is the one
	// thing the use case's contract forbids and the handler must survive.
	inlineBuild func(cmd app.IntakeCommand) *domain.Receipt
	err         error

	// block holds the overflow worker still so a test can fill the backlog behind
	// it; started is closed the first time that happens, so the test can wait for
	// the worker to be genuinely busy instead of racing it.
	block   chan struct{}
	started chan struct{}
	once    sync.Once

	mu    sync.Mutex
	calls int
}

func (f *fakeRunner) Intake(ctx context.Context, cmd app.IntakeCommand) (*domain.Receipt, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	// A context with NO deadline is the worker calling: the inline attempt always
	// runs under the inline budget, and the worker deliberately does not, because
	// the work must outlive the request that handed it over.
	_, inline := ctx.Deadline()
	if f.block != nil && !inline {
		f.once.Do(func() { close(f.started) })
		<-f.block
	}
	build := f.build
	if inline && f.inlineBuild != nil {
		build = f.inlineBuild
	}
	if build == nil {
		return nil, f.err
	}
	return build(cmd), f.err
}

func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeReceipts is an in-memory receipt store with the one behaviour that matters:
// a second write under an asserted key that another receipt already owns is reported
// as a taken key, not as a failure.
type fakeReceipts struct {
	mu      sync.Mutex
	byID    map[string]store.IntakeReceipt
	byKey   map[string]string
	saves   int
	saveErr error
	findErr error
	// findMisses makes the next N key lookups report "not found" while the key is
	// already taken in the constraint — the state the loser of a concurrent race
	// wakes up in, and the only way to reach the taken-key branch from a test.
	findMisses int
	failed     []string // the details FailStaleNonTerminalReceipts was called with
}

func newReceipts() *fakeReceipts {
	return &fakeReceipts{byID: map[string]store.IntakeReceipt{}, byKey: map[string]string{}}
}

func (f *fakeReceipts) SaveIntakeReceipt(_ context.Context, r store.IntakeReceipt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	if r.IdempotencyKey != "" {
		if owner, ok := f.byKey[r.IdempotencyKey]; ok && owner != r.IntakeID {
			return store.ErrIdempotencyKeyTaken
		}
		f.byKey[r.IdempotencyKey] = r.IntakeID
	}
	if prev, ok := f.byID[r.IntakeID]; ok {
		r.CreatedAt = prev.CreatedAt
	} else {
		r.CreatedAt = time.Unix(1_700_000_000, 0).UTC()
	}
	r.UpdatedAt = time.Unix(1_700_000_001, 0).UTC()
	f.byID[r.IntakeID] = r
	f.saves++
	return nil
}

func (f *fakeReceipts) LoadIntakeReceipt(_ context.Context, id string) (store.IntakeReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.byID[id]
	if !ok {
		return store.IntakeReceipt{}, store.ErrNotFound
	}
	return r, nil
}

func (f *fakeReceipts) FindIntakeReceiptByIdempotencyKey(_ context.Context, key string) (store.IntakeReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.findErr != nil {
		return store.IntakeReceipt{}, f.findErr
	}
	if f.findMisses > 0 {
		f.findMisses--
		return store.IntakeReceipt{}, store.ErrNotFound
	}
	id, ok := f.byKey[key]
	if !ok {
		return store.IntakeReceipt{}, store.ErrNotFound
	}
	return f.byID[id], nil
}

func (f *fakeReceipts) FailStaleNonTerminalReceipts(_ context.Context, _ time.Time, detail string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, detail)
	return len(f.failed), nil
}

func (f *fakeReceipts) saveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saves
}

// fakeInventory answers the component count a filed SBOM's receipt reports.
type fakeInventory struct {
	inv domain.Inventory
	err error
}

func (f fakeInventory) GetInventory(context.Context, domain.EvidenceID) (domain.Inventory, error) {
	return f.inv, f.err
}

// --- helpers ----------------------------------------------------------------

// filed builds the receipt a successful attempt leaves, walking the real ladder so
// the test cannot construct a state the domain would refuse.
func filed(t *testing.T, cmd app.IntakeCommand, kind, dialect, evidenceID string, created bool) *domain.Receipt {
	t.Helper()
	r := &domain.Receipt{}
	must(t, r.Accept())
	must(t, r.StartValidating())
	must(t, r.RecordDetected(kind, dialect))
	must(t, r.RecordRelease(releaseOf(cmd)))
	if kind != "sbom" {
		must(t, r.StartConverting())
		must(t, r.RecordConversion("cortex@1", "d1ge57", 427, 0))
	}
	must(t, r.StartRegistering())
	must(t, r.Filed(evidenceID, created))
	return r
}

func rejected(t *testing.T, reason domain.RejectReason, detail string) *domain.Receipt {
	t.Helper()
	r := &domain.Receipt{}
	must(t, r.Accept())
	must(t, r.Rejected(reason, detail))
	return r
}

func failedReceipt(t *testing.T, detail string) *domain.Receipt {
	t.Helper()
	r := &domain.Receipt{}
	must(t, r.Accept())
	must(t, r.Failed(detail))
	return r
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
}

func releaseOf(cmd app.IntakeCommand) string {
	if cmd.ReleaseID != "" {
		return cmd.ReleaseID
	}
	return "rel-resolved"
}

type intakeFixture struct {
	handler  http.Handler
	runner   *fakeRunner
	receipts *fakeReceipts
	intake   *evhttp.Intake
}

func newIntakeFixture(t *testing.T, cfg evhttp.IntakeConfig, runner *fakeRunner, inv evhttp.InventoryCounter) intakeFixture {
	t.Helper()
	receipts := newReceipts()
	intake := evhttp.NewIntake(runner, receipts, inv, cfg, nil)
	t.Cleanup(intake.Close)
	return intakeFixture{
		handler:  evhttp.NewHandler(nil).WithIntake(intake).Router(),
		runner:   runner,
		receipts: receipts,
		intake:   intake,
	}
}

// post submits a body to the intake door. Extra headers come last so a test can
// assert an Idempotency-Key without a second helper.
func post(t *testing.T, h http.Handler, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeReceipt(t *testing.T, rec *httptest.ResponseRecorder) gen.IntakeReceipt {
	t.Helper()
	var out gen.IntakeReceipt
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode receipt from %s: %v", rec.Body.String(), err)
	}
	return out
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) gen.IntakeProblem {
	t.Helper()
	var out gen.IntakeProblem
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode problem from %s: %v", rec.Body.String(), err)
	}
	return out
}

// --- the reason -> status contract (D11) ------------------------------------

// TestIntakeReasonToHTTPStatus_CoversTheWholeTaxonomy walks the CLOSED taxonomy
// against D11's table through the real handler. A reason added without a status
// fails here rather than quietly becoming a 422 — which is #116's cost in one
// sentence: a consumer that knew 6 of 15 reasons reported "no reason given" for the
// other nine.
func TestIntakeReasonToHTTPStatus_CoversTheWholeTaxonomy(t *testing.T) {
	want := map[domain.RejectReason]int{
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
		domain.ReasonUnauthorized:           http.StatusUnauthorized,
	}
	reasons := domain.AllRejectReasons()
	if len(want) != len(reasons) {
		t.Fatalf("the table maps %d reasons and the taxonomy has %d; D11's table and the enum must agree", len(want), len(reasons))
	}

	for _, reason := range reasons {
		code, ok := want[reason]
		if !ok {
			t.Fatalf("reason %q has no status in D11's table", reason)
		}
		t.Run(string(reason), func(t *testing.T) {
			runner := &fakeRunner{build: func(app.IntakeCommand) *domain.Receipt {
				return rejected(t, reason, "the elaboration")
			}}
			f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)
			rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[]}`, nil)
			if rec.Code != code {
				t.Errorf("status = %d, want %d", rec.Code, code)
			}
			p := decodeProblem(t, rec)
			if p.Reason == nil || string(*p.Reason) != string(reason) {
				t.Errorf("reason = %v, want %q", p.Reason, reason)
			}
			if p.Status != code {
				t.Errorf("problem.status = %d, want %d", p.Status, code)
			}
		})
	}
}

// TestIntakeRefusal_ReasonAndDetailStaySeparate — Governance flattened exactly this
// pair into "<reason>: <detail>", which turned a closed enum into free text and made
// every consumer's table lookup miss: a safety refusal reached the operator as "no
// reason given" (fixed 2026-09-22). A consumer switches on the reason and displays
// the detail, so the wire carries two fields.
func TestIntakeRefusal_ReasonAndDetailStaySeparate(t *testing.T) {
	const detail = "finding[0]: 'cve' is required; found keys: asset_name, package_purl"
	runner := &fakeRunner{build: func(app.IntakeCommand) *domain.Receipt {
		return rejected(t, domain.ReasonSchemaInvalid, detail)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", `[{"vendor":"cortex"}]`, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d", rec.Code)
	}

	// Asserted on the raw JSON, not the decoded struct: the defect was a producer
	// writing one field, and a decode into two fields would hide it.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["reason"] != string(domain.ReasonSchemaInvalid) {
		t.Errorf("reason = %v", raw["reason"])
	}
	if raw["detail"] != detail {
		t.Errorf("detail = %v, want the elaboration alone", raw["detail"])
	}
	if raw["intake_id"] == "" || raw["intake_id"] == nil {
		t.Error("the refusal names no receipt; a rejected receipt is what was missing on 2026-10-05")
	}
}

// TestIntakeRefusal_PersistsARejectedReceipt — D9's whole point. The attempt is
// addressable afterwards, and nothing else was written.
func TestIntakeRefusal_PersistsARejectedReceipt(t *testing.T) {
	runner := &fakeRunner{build: func(app.IntakeCommand) *domain.Receipt {
		return rejected(t, domain.ReasonUnrecognisedFormat, "the body matches no known dialect")
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"vendor":"who?"}`, nil)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d", rec.Code)
	}
	id := *decodeProblem(t, rec).IntakeId

	got := httptest.NewRecorder()
	f.handler.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/intake/"+id, nil))
	if got.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200: the receipt is the answer, whatever it says", got.Code)
	}
	view := decodeReceipt(t, got)
	if view.Status != "rejected" || view.Reason == nil || *view.Reason != gen.UnrecognisedFormat {
		t.Errorf("receipt = %+v, want a rejected receipt naming its reason", view)
	}
	if view.StatusUrl != "/api/v1/intake/"+id {
		t.Errorf("status_url = %q", view.StatusUrl)
	}
}

func TestIntakeReceipt_UnknownIDIs404(t *testing.T) {
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, &fakeRunner{}, nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/intake/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// --- the fast path ----------------------------------------------------------

// TestIntakeFiled_201CarriesWhatLanded — the counts are the client's file-note UX
// (the GUI reads them straight off this response), and both are reported: "427 of
// 427" and "427 of 500" must not look alike.
func TestIntakeFiled_201CarriesWhatLanded(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "cortex-json", "ev-77", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{
		KnowledgeURL:  "http://knowledge:8085",
		GovernanceURL: "http://governance:8083/",
	}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body)
	}
	view := decodeReceipt(t, rec)
	if view.Status != "filed" || view.EvidenceId == nil || *view.EvidenceId != "ev-77" {
		t.Fatalf("receipt = %+v", view)
	}
	if view.Created == nil || !*view.Created {
		t.Error("created is not true on a 201")
	}
	if view.FindingsTotal == nil || *view.FindingsTotal != 427 || view.FindingsSkipped == nil || *view.FindingsSkipped != 0 {
		t.Errorf("counts = %v / %v, want both reported", view.FindingsTotal, view.FindingsSkipped)
	}
	if view.ConvertedBy == nil || *view.ConvertedBy != "cortex@1" {
		t.Errorf("converted_by = %v", view.ConvertedBy)
	}
	if view.DetectedFormat == nil || *view.DetectedFormat != "cortex-json" {
		t.Errorf("detected_format = %v", view.DetectedFormat)
	}
	if view.SourceDigest == nil || *view.SourceDigest != "d1ge57" {
		t.Errorf("source_digest = %v", view.SourceDigest)
	}

	// D10: the receipt is terminal at `filed` and does NOT claim correlation is
	// complete — it names who answers that instead.
	if view.NextChecks == nil || len(*view.NextChecks) != 2 {
		t.Fatalf("next_checks = %v, want unresolved + posture", view.NextChecks)
	}
	checks := *view.NextChecks
	if checks[0].What != "unresolved" || checks[0].Url != "http://knowledge:8085/api/v1/scanner-reports/ev-77/unresolved" {
		t.Errorf("unresolved check = %+v", checks[0])
	}
	if checks[1].What != "posture" || checks[1].Url != "http://governance:8083/api/v1/releases/rel-1/posture" {
		t.Errorf("posture check = %+v (a trailing slash on the base URL must not double up)", checks[1])
	}
}

// TestIntakeFiled_DedupIs200AndCreatedFalse — D8: a byte-identical re-submission to
// the same release files nothing twice, and says so.
func TestIntakeFiled_DedupIs200AndCreatedFalse(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "curated", "ev-77", false)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if c := decodeReceipt(t, rec).Created; c == nil || *c {
		t.Errorf("created = %v, want an explicit false when nothing was created", c)
	}
}

// TestIntakeFiled_SBOMReportsItsComponentCount — read back after filing, so the
// receipt reports what actually landed rather than what the request hoped for.
func TestIntakeFiled_SBOMReportsItsComponentCount(t *testing.T) {
	purl, err := value.NewPURL("pkg:deb/debian/openssl@3.0.11")
	if err != nil {
		t.Fatal(err)
	}
	inv := domain.NewInventory([]domain.Component{{PURL: purl, Name: "openssl", Version: "3.0.11", Ecosystem: "deb"}}, nil)
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "sbom", "spdx", "ev-sbom", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{GovernanceURL: "http://governance:8083"}, runner, fakeInventory{inv: inv})

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"spdxVersion":"SPDX-2.3"}`, nil)
	view := decodeReceipt(t, rec)
	if view.Components == nil || *view.Components != 1 {
		t.Errorf("components = %v, want 1", view.Components)
	}
	// An SBOM has no scanner report to ask about, so only the posture check applies.
	if view.NextChecks == nil || len(*view.NextChecks) != 1 || (*view.NextChecks)[0].What != "posture" {
		t.Errorf("next_checks = %v, want posture alone", view.NextChecks)
	}
}

// TestIntakeFiled_AnUnreadableInventoryCountIsStillFiled — the document landed; a
// count we could not read is a gap in the receipt, never a reason to call the filing
// anything but filed.
func TestIntakeFiled_AnUnreadableInventoryCountIsStillFiled(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "sbom", "spdx", "ev-sbom", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, fakeInventory{err: errors.New("gone")})

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"spdxVersion":"SPDX-2.3"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if c := decodeReceipt(t, rec).Components; c != nil && *c != 0 {
		t.Errorf("components = %v, want 0 when the count could not be read", c)
	}
}

// TestIntakeNextChecks_OmittedWhenTheBaseURLsAreUnset — a client can tell "nobody
// told me where to look" from a URL that 404s; it cannot tell a broken URL from a
// broken pipeline.
func TestIntakeNextChecks_OmittedWhenTheBaseURLsAreUnset(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "trivy", "ev-77", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["next_checks"]; present {
		t.Errorf("next_checks is present with no base URLs configured: %v", raw["next_checks"])
	}
}

// TestIntakeFailed_IsNotARefusal — an UNTYPED write failure is a statement about
// Themis, not about the document, so it carries NO reason. Inventing one would send
// the operator to fix a document that was never the problem. (The typed refusals that
// DO have a name are the test above.)
func TestIntakeFailed_IsNotARefusal(t *testing.T) {
	runner := &fakeRunner{
		build: func(app.IntakeCommand) *domain.Receipt { return failedReceipt(t, "register: connection refused") },
		err:   errors.New("connection refused"),
	}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if p := decodeProblem(t, rec); p.Reason != nil {
		t.Errorf("reason = %v, want none on a failure", *p.Reason)
	}
}

// TestIntakeFiling_TypedRefusalsKeepTheirName — the filing step reports its refusals
// as errors, so without this translation a cross-release duplicate reads as a server
// fault. D8 requires it to stay the loud 409 it has always been: returning the other
// release's id used to read as success, measured live on 2026-08-19, and the caller's
// release had received nothing.
func TestIntakeFiling_TypedRefusalsKeepTheirName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cause  error
		reason gen.RejectReason
		status int
	}{
		{
			name:   "byte-identical content filed against another release",
			cause:  &app.ContentFiledElsewhereError{EvidenceID: "ev-other", ReleaseID: "rel-2"},
			reason: gen.DuplicateOtherRelease,
			status: http.StatusConflict,
		},
		{
			name:   "the release vanished between resolution and the write",
			cause:  app.ErrUnknownSubject,
			reason: gen.UnknownRelease,
			status: http.StatusNotFound,
		},
		{
			name:   "the trust gate and the border disagree about the document",
			cause:  app.ErrRejected,
			reason: gen.SchemaInvalid,
			status: http.StatusUnprocessableEntity,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{
				build: func(app.IntakeCommand) *domain.Receipt { return failedReceipt(t, "register: "+tc.cause.Error()) },
				err:   tc.cause,
			}
			f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

			rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Reason == nil || *p.Reason != tc.reason {
				t.Fatalf("reason = %v, want %q", p.Reason, tc.reason)
			}
			// And the stored receipt says the same thing: a response that names a
			// refusal over a receipt that says "failed" is two answers to one question.
			view := readStoredReceipt(t, f.handler, *p.IntakeId)
			if view.Status != "rejected" || view.Reason == nil || *view.Reason != tc.reason {
				t.Errorf("stored receipt = %+v", view)
			}
		})
	}
}

func readStoredReceipt(t *testing.T, h http.Handler, intakeID string) gen.IntakeReceipt {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/intake/"+intakeID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /intake/%s = %d: %s", intakeID, rec.Code, rec.Body)
	}
	return decodeReceipt(t, rec)
}

// TestIntake_ANilReceiptIsAFailureNotAPanic — unreachable through the use case, whose
// contract is that every outcome is on the receipt. Asserted because the alternative
// is a nil dereference that takes the node down.
func TestIntake_ANilReceiptIsAFailureNotAPanic(t *testing.T) {
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, &fakeRunner{err: errors.New("boom")}, nil)
	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[]}`, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// --- border checks the edge owns -------------------------------------------

// TestIntakeBodyBound_RefusesBeforeBuffering — D13. The bound is checked before the
// body is read into memory, because a limit applied after the read protects nothing
// it was meant to.
func TestIntakeBodyBound_RefusesBeforeBuffering(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "curated", "ev-1", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{MaxBytes: 32}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", strings.Repeat("x", 4096), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if p := decodeProblem(t, rec); p.Reason == nil || *p.Reason != gen.PayloadTooLarge {
		t.Errorf("reason = %v, want payload_too_large", p.Reason)
	}
	if f.runner.callCount() != 0 {
		t.Error("the use case was called for a body that was refused at the border")
	}
}

// TestIntakeExpectedChecksum_IsVerifiedOverTheSUBMITTEDBytes — and that is the only
// place it can be right: for a converted submission the filed bytes are not the bytes
// the caller hashed (D2), so a gate downstream of the converter would compare the
// assertion against a different document.
func TestIntakeExpectedChecksum_IsVerifiedOverTheSUBMITTEDBytes(t *testing.T) {
	body := `{"findings":[{"cve":"CVE-1"}]}`
	digest := value.NewContentFingerprint([]byte(body)).String()
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "curated", "ev-1", true)
	}}

	t.Run("matching", func(t *testing.T) {
		f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)
		// Upper case and padded, because an operator pasting a digest is how this
		// gets used and a case-sensitive compare would refuse a correct checksum.
		target := "/intake?release_id=rel-1&expected_checksum=" + strings.ToUpper(digest)
		if rec := post(t, f.handler, target, body, nil); rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body)
		}
	})

	t.Run("mismatched", func(t *testing.T) {
		f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)
		rec := post(t, f.handler, "/intake?release_id=rel-1&expected_checksum="+strings.Repeat("a", 64), body, nil)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		p := decodeProblem(t, rec)
		if p.Reason == nil || *p.Reason != gen.ChecksumMismatch {
			t.Fatalf("reason = %v, want checksum_mismatch", p.Reason)
		}
		if !strings.Contains(p.Detail, digest) {
			t.Errorf("detail %q does not name the digest Themis computed, which is what the operator needs to compare", p.Detail)
		}
	})
}

// TestIntakeObservedAt_PresentButImplausibleIsNamed — D3/D11. Never a silent fallback
// to `now`: a report stamped fresh and re-uploaded tomorrow is a second scan of the
// same image, and no operator can tell it from a real one.
func TestIntakeObservedAt_PresentButImplausibleIsNamed(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "curated", "ev-1", true)
	}}
	for _, tc := range []struct {
		name, value, wantIn string
	}{
		{"unparseable", "last-tuesday", "RFC 3339"},
		{"pre-2000", "1998-04-01T00:00:00Z", "implausible"},
		{"far future", time.Now().UTC().Add(72 * time.Hour).Format(time.RFC3339), "future"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)
			rec := post(t, f.handler, "/intake?release_id=rel-1&observed_at="+tc.value, `{"findings":[{"cve":"CVE-1"}]}`, nil)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422", rec.Code)
			}
			p := decodeProblem(t, rec)
			if p.Reason == nil || *p.Reason != gen.ObservedAtInvalid {
				t.Fatalf("reason = %v, want observed_at_invalid", p.Reason)
			}
			if !strings.Contains(p.Detail, tc.wantIn) {
				t.Errorf("detail %q does not say why", p.Detail)
			}
		})
	}
}

// TestIntakeObservedAt_SuppliedValueReachesTheUseCase — a supplied timestamp is an
// assertion about WHICH observation this is, so it must reach the converter: the same
// file with a different supplied timestamp correctly does not dedup (D3).
func TestIntakeObservedAt_SuppliedValueReachesTheUseCase(t *testing.T) {
	var seen app.IntakeCommand
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		seen = cmd
		return filed(t, cmd, "vuln-report", "curated", "ev-1", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

	post(t, f.handler, "/intake?release_id=rel-1&observed_at=2026-09-29T07:23:22Z&allow_without_sbom=true&product=OAMP&project=core&version=R1&provenance_source=cortex&provenance_image_digest=sha256:abc",
		`{"findings":[{"cve":"CVE-1"}]}`, nil)

	want := time.Date(2026, 9, 29, 7, 23, 22, 0, time.UTC)
	if !seen.ObservedAt.Equal(want) {
		t.Errorf("observed_at = %v, want %v", seen.ObservedAt, want)
	}
	if !seen.AllowWithoutSBOM {
		t.Error("allow_without_sbom did not reach the use case; D6's override would be silently ignored")
	}
	if seen.Product != "OAMP" || seen.Project != "core" || seen.Version != "R1" || seen.ReleaseID != "rel-1" {
		t.Errorf("release metadata = %+v", seen)
	}
	if seen.ProvenanceSource != "cortex" || seen.ProvenanceImageDigest != "sha256:abc" {
		t.Errorf("provenance = %q / %q", seen.ProvenanceSource, seen.ProvenanceImageDigest)
	}
	if seen.ContentType != "application/json" {
		t.Errorf("content type = %q, and it is decisive for CSV", seen.ContentType)
	}
}

// --- idempotency (D12) ------------------------------------------------------

// TestIdempotencyKey_ReplayReturnsTheOriginalReceipt — the same key within the TTL
// returns the ORIGINAL receipt rather than starting new work. Asserted on both halves:
// the same intake id comes back, and the use case is not called a second time.
func TestIdempotencyKey_ReplayReturnsTheOriginalReceipt(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "curated", "ev-1", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)
	headers := map[string]string{"Idempotency-Key": "upload-1"}
	const body = `{"findings":[{"cve":"CVE-1"}]}`

	first := post(t, f.handler, "/intake?release_id=rel-1", body, headers)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want 201: %s", first.Code, first.Body)
	}
	firstID := decodeReceipt(t, first).IntakeId

	second := post(t, f.handler, "/intake?release_id=rel-1", body, headers)
	// 200, not 201: the receipt already existed and THIS request created nothing.
	if second.Code != http.StatusOK {
		t.Fatalf("replay status = %d, want 200", second.Code)
	}
	replay := decodeReceipt(t, second)
	if replay.IntakeId != firstID {
		t.Errorf("replay intake_id = %q, want the original %q", replay.IntakeId, firstID)
	}
	if replay.EvidenceId == nil || *replay.EvidenceId != "ev-1" {
		t.Errorf("replay evidence_id = %v", replay.EvidenceId)
	}
	if f.runner.callCount() != 1 {
		t.Errorf("the use case ran %d times; a replay must file nothing", f.runner.callCount())
	}
}

// TestIdempotencyKey_ReplayOfARefusalIsTheSameRefusal — a retry of a refused upload
// gets the refusal back, not a second attempt at the same bad document.
func TestIdempotencyKey_ReplayOfARefusalIsTheSameRefusal(t *testing.T) {
	runner := &fakeRunner{build: func(app.IntakeCommand) *domain.Receipt {
		return rejected(t, domain.ReasonEmptyReport, "zero findings")
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)
	headers := map[string]string{"Idempotency-Key": "upload-2"}

	first := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[]}`, headers)
	second := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[]}`, headers)
	if first.Code != http.StatusUnprocessableEntity || second.Code != http.StatusUnprocessableEntity {
		t.Fatalf("statuses = %d, %d; want 422 both times", first.Code, second.Code)
	}
	if *decodeProblem(t, first).IntakeId != *decodeProblem(t, second).IntakeId {
		t.Error("the replay got a different receipt")
	}
	if f.runner.callCount() != 1 {
		t.Errorf("the use case ran %d times", f.runner.callCount())
	}
}

// TestIdempotencyKey_ALostRaceReturnsTheWinnersReceipt — two concurrent first-time
// requests with one key both miss the lookup; the loser's INSERT violates the UNIQUE
// constraint, and that is a retry arriving, not a persistence failure.
func TestIdempotencyKey_ALostRaceReturnsTheWinnersReceipt(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "curated", "ev-1", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

	// Seed the key against a receipt this request does not own — the winner — and
	// make the first lookup miss, which is exactly the state the loser wakes up in.
	if err := f.receipts.SaveIntakeReceipt(context.Background(), store.IntakeReceipt{
		IntakeID: "winner", IdempotencyKey: "upload-3", Status: domain.ReceiptFiled, EvidenceID: "ev-winner",
	}); err != nil {
		t.Fatal(err)
	}
	f.receipts.mu.Lock()
	f.receipts.findMisses = 1
	f.receipts.mu.Unlock()

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, map[string]string{"Idempotency-Key": "upload-3"})
	if rec.Code >= 500 {
		t.Fatalf("status = %d: a duplicate key must never read as a persistence failure: %s", rec.Code, rec.Body)
	}
	view := decodeReceipt(t, rec)
	if view.IntakeId != "winner" || view.EvidenceId == nil || *view.EvidenceId != "ev-winner" {
		t.Errorf("receipt = %+v, want the winner's", view)
	}
}

// TestIdempotencyKey_AnUnreadableLookupIsAFailureNotAFreshAttempt — if we cannot tell
// whether this key already filed something, starting fresh work risks filing twice.
func TestIdempotencyKey_AnUnreadableLookupIsAFailureNotAFreshAttempt(t *testing.T) {
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, &fakeRunner{}, nil)
	f.receipts.mu.Lock()
	f.receipts.findErr = errors.New("connection refused")
	f.receipts.mu.Unlock()

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[]}`, map[string]string{"Idempotency-Key": "k"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if f.runner.callCount() != 0 {
		t.Error("work started while the key's state was unknown")
	}
}

// TestIntake_AReceiptThatCannotBeWrittenIsA500 — the receipt IS the answer, so a
// request whose outcome could not be recorded must not report success.
func TestIntake_AReceiptThatCannotBeWrittenIsA500(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "curated", "ev-1", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)
	f.receipts.mu.Lock()
	f.receipts.saveErr = errors.New("disk full")
	f.receipts.mu.Unlock()

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// TestIntakeRefusal_ThatCannotBeRecordedIsA500 — same rule on the refusal path.
func TestIntakeRefusal_ThatCannotBeRecordedIsA500(t *testing.T) {
	f := newIntakeFixture(t, evhttp.IntakeConfig{MaxBytes: 8}, &fakeRunner{}, nil)
	f.receipts.mu.Lock()
	f.receipts.saveErr = errors.New("disk full")
	f.receipts.mu.Unlock()

	rec := post(t, f.handler, "/intake?release_id=rel-1", strings.Repeat("x", 64), nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// TestIntakeBody_AnUnreadableRequestIsMalformedNotEmpty — a body that could not be
// read is `malformed_body`: we do not know what we were reading, and treating a
// truncated upload as an empty document would file nothing and call it success.
func TestIntakeBody_AnUnreadableRequestIsMalformedNotEmpty(t *testing.T) {
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, &fakeRunner{}, nil)

	req := httptest.NewRequest(http.MethodPost, "/intake?release_id=rel-1", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	req.Body = errReader{}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if p := decodeProblem(t, rec); p.Reason == nil || *p.Reason != gen.MalformedBody {
		t.Errorf("reason = %v, want malformed_body", p.Reason)
	}
	if f.runner.callCount() != 0 {
		t.Error("the use case ran on a body that could not be read")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (errReader) Close() error             { return nil }

// --- the slow path and the bounded backlog (D9) ----------------------------

// TestIntakeSlowPath_202ThenTheReceiptReachesFiled — the work continues server-side
// and the receipt advances on its own, which is the whole of what `202` promises.
func TestIntakeSlowPath_202ThenTheReceiptReachesFiled(t *testing.T) {
	runner := &fakeRunner{
		// The inline attempt ran out of time before anything landed...
		inlineBuild: func(app.IntakeCommand) *domain.Receipt {
			return failedReceipt(t, "the inline budget ran out")
		},
		// ...so the attempt is retried from the start on the worker, which files it.
		build: func(cmd app.IntakeCommand) *domain.Receipt {
			return filed(t, cmd, "vuln-report", "cortex-csv", "ev-slow", true)
		},
	}
	// A budget this small forces the overflow path deterministically, which is also
	// how the integration test drives it.
	f := newIntakeFixture(t, evhttp.IntakeConfig{InlineBudget: time.Nanosecond}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
	}
	view := decodeReceipt(t, rec)
	if view.Status != "accepted" {
		t.Errorf("status = %q, want accepted", view.Status)
	}
	if view.RetryAfterSeconds == nil || *view.RetryAfterSeconds <= 0 {
		t.Errorf("retry_after_seconds = %v, want a hint the client can act on", view.RetryAfterSeconds)
	}
	if view.StatusUrl != "/api/v1/intake/"+view.IntakeId {
		t.Errorf("status_url = %q", view.StatusUrl)
	}

	waitFor(t, func() bool {
		r, err := f.receipts.LoadIntakeReceipt(context.Background(), view.IntakeId)
		return err == nil && r.Status == domain.ReceiptFiled && r.EvidenceID == "ev-slow"
	}, "the receipt never reached filed")
}

// TestIntakeSlowPath_AWorkerFaultLeavesTheReceiptForTheNextStartup — the client is
// holding a status URL, so there is nothing to tell it: the log is the only honest
// record, and a receipt left non-terminal is closed out by the next startup's
// recovery sweep rather than claiming an outcome nobody observed.
func TestIntakeSlowPath_AWorkerFaultLeavesTheReceiptForTheNextStartup(t *testing.T) {
	inlineRanOut := func(app.IntakeCommand) *domain.Receipt {
		return failedReceipt(t, "the inline budget ran out")
	}
	for _, tc := range []struct {
		name string
		// workerBuild nil means the use case returns no receipt at all on the worker.
		workerBuild func(cmd app.IntakeCommand) *domain.Receipt
		breakSave   bool
	}{
		{name: "the use case returned no receipt"},
		{
			name: "the receipt could not be advanced",
			workerBuild: func(cmd app.IntakeCommand) *domain.Receipt {
				return filed(t, cmd, "vuln-report", "curated", "ev-slow", true)
			},
			breakSave: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release, started := make(chan struct{}), make(chan struct{})
			runner := &fakeRunner{
				inlineBuild: inlineRanOut,
				build:       tc.workerBuild,
				err:         errors.New("boom"),
				block:       release,
				started:     started,
			}
			// An explicit logger, because a worker fault's only report is what it
			// logs and the nil-logger default must not be the only path exercised.
			receipts := newReceipts()
			intake := evhttp.NewIntake(runner, receipts, nil, evhttp.IntakeConfig{InlineBudget: time.Nanosecond}, observability.Nop())
			t.Cleanup(intake.Close)
			handler := evhttp.NewHandler(nil).WithIntake(intake).Router()

			rec := post(t, handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body)
			}
			id := decodeReceipt(t, rec).IntakeId

			// The worker is held before it does anything, so the fault is in place
			// BEFORE the work runs rather than racing it.
			<-started
			if tc.breakSave {
				receipts.mu.Lock()
				receipts.saveErr = errors.New("disk full")
				receipts.mu.Unlock()
			}
			close(release)
			intake.Close() // drains the backlog

			got, err := receipts.LoadIntakeReceipt(context.Background(), id)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got.Status == domain.ReceiptFiled {
				t.Errorf("receipt reached %q although the worker could not record it", got.Status)
			}
		})
	}
}

// TestIntakeBacklogFull_503CreatesNoReceipt — nothing was accepted, nothing was
// filed, and there is no receipt to find, so the whole request is safe to retry
// verbatim. That is what makes the backlog check belong BEFORE the receipt write.
func TestIntakeBacklogFull_503CreatesNoReceipt(t *testing.T) {
	release, started := make(chan struct{}), make(chan struct{})
	runner := &fakeRunner{
		// Deliberately not using the t-aware helper: this receipt is built on the
		// worker's goroutine, which outlives the test body.
		build: func(app.IntakeCommand) *domain.Receipt {
			r := &domain.Receipt{}
			_ = r.Accept()
			_ = r.Failed("the inline budget ran out")
			return r
		},
		block:   release,
		started: started,
	}
	f := newIntakeFixture(t, evhttp.IntakeConfig{InlineBudget: time.Nanosecond}, runner, nil)
	defer close(release)

	const body = `{"findings":[{"cve":"CVE-1"}]}`
	accepted := 0
	submit := func(n int) *httptest.ResponseRecorder {
		rec := post(t, f.handler, "/intake?release_id=rel-1", body, nil)
		if rec.Code == http.StatusAccepted {
			accepted++
		}
		return rec
	}

	// The first submission is the one the worker picks up; waiting for it to be
	// genuinely busy is what keeps the capacity arithmetic below from racing it.
	if rec := submit(0); rec.Code != http.StatusAccepted {
		t.Fatalf("first submission: status = %d, want 202: %s", rec.Code, rec.Body)
	}
	<-started

	for n := 0; n < evhttp.IntakeQueueCapacity; n++ {
		if rec := submit(n + 1); rec.Code != http.StatusAccepted {
			t.Fatalf("submission %d: status = %d, want 202: %s", n+1, rec.Code, rec.Body)
		}
	}

	full := submit(evhttp.IntakeQueueCapacity + 1)
	if full.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 once the backlog is full", full.Code)
	}
	if full.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After: a 503 the client cannot time is a 503 it will hammer")
	}
	if got := f.receipts.saveCount(); got != accepted {
		t.Errorf("%d receipts written for %d accepted submissions; the refused one must leave none", got, accepted)
	}
}

// TestIntakeSlowPath_AReceiptThatCannotBeReservedIsA500 — a `202` whose receipt was
// not written would hand the client a status URL that answers 404 forever.
func TestIntakeSlowPath_AReceiptThatCannotBeReservedIsA500(t *testing.T) {
	runner := &fakeRunner{inlineBuild: func(app.IntakeCommand) *domain.Receipt {
		return failedReceipt(t, "the inline budget ran out")
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{InlineBudget: time.Nanosecond}, runner, nil)
	f.receipts.mu.Lock()
	f.receipts.saveErr = errors.New("disk full")
	f.receipts.mu.Unlock()

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// TestIntakeAfterClose_Is503NotAPanic — a submission arriving mid-shutdown must not
// send on a closed channel.
func TestIntakeAfterClose_Is503NotAPanic(t *testing.T) {
	runner := &fakeRunner{build: func(app.IntakeCommand) *domain.Receipt { return failedReceipt(t, "budget") }}
	f := newIntakeFixture(t, evhttp.IntakeConfig{InlineBudget: time.Nanosecond}, runner, nil)
	f.intake.Close()
	f.intake.Close() // idempotent

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// TestIntakeSlowPath_ARefusalReachedInlineIsStillARefusal — a verdict the use case
// reached before the budget expired stands; only an attempt that did not land is
// retried. Without this the fast path would be bypassed by every slow estate.
func TestIntakeSlowPath_ARefusalReachedInlineIsStillARefusal(t *testing.T) {
	runner := &fakeRunner{build: func(app.IntakeCommand) *domain.Receipt {
		return rejected(t, domain.ReasonEmptyReport, "zero findings")
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{InlineBudget: time.Minute}, runner, nil)

	rec := post(t, f.handler, "/intake?release_id=rel-1", `{"findings":[]}`, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", rec.Code)
	}
}

// --- startup recovery -------------------------------------------------------

// TestRecoverInterruptedReceipts_NamesTheActionNotJustTheFailure — a receipt stuck at
// `accepted` after a crash would have a client polling a goroutine that no longer
// exists, so the next process closes it out and says what to do.
func TestRecoverInterruptedReceipts_NamesTheActionNotJustTheFailure(t *testing.T) {
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, &fakeRunner{}, nil)

	n, err := f.intake.RecoverInterruptedReceipts(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("recovered %d, %v", n, err)
	}
	f.receipts.mu.Lock()
	defer f.receipts.mu.Unlock()
	if len(f.receipts.failed) != 1 || !strings.Contains(f.receipts.failed[0], "resubmit") {
		t.Errorf("recovery detail = %v, want it to name the action", f.receipts.failed)
	}
}

// --- the inbound auth edge (EDR-SECURITY-01 F1) -----------------------------

// fakeKeys is the identity store the platform authenticator reads. The comparison
// below is injected too, so the test spends no time on bcrypt.
type fakeKeys struct{ keys []auth.APIKey }

func (f fakeKeys) ActiveKeys(context.Context) ([]auth.APIKey, error) { return f.keys, nil }

// TestIntake_SitsBehindTheInboundAuthEdge — the door adds no auth of its own and
// needs none: it is mounted inside the SAME authenticated group as every other
// `/api/v1` route, exactly as cmd/evidence mounts it. What this pins is that the
// mount is real, because a new route added outside that group would be an open write
// surface and nothing else would notice.
func TestIntake_SitsBehindTheInboundAuthEdge(t *testing.T) {
	runner := &fakeRunner{build: func(cmd app.IntakeCommand) *domain.Receipt {
		return filed(t, cmd, "vuln-report", "curated", "ev-1", true)
	}}
	f := newIntakeFixture(t, evhttp.IntakeConfig{}, runner, nil)

	authn := auth.Authenticator{
		Keys: fakeKeys{keys: []auth.APIKey{
			{ID: "k-admin", Name: "ci", KeyHash: "hash-admin", Scopes: []string{auth.ScopeAdmin}},
			{ID: "k-read", Name: "viewer", KeyHash: "hash-read", Scopes: []string{auth.ScopeRead}},
		}},
		Compare: func(hashed, presented []byte) error {
			if string(hashed) == "hash-"+string(presented) {
				return nil
			}
			return errors.New("mismatch")
		},
	}
	router := chi.NewRouter()
	router.Group(func(r chi.Router) {
		r.Use(authn.RequireAPIKey)
		r.Use(auth.RequireWriteScope)
		r.Mount("/api/v1", f.handler)
	})

	for _, tc := range []struct {
		name, key string
		want      int
	}{
		{"no key at all", "", http.StatusUnauthorized},
		{"an unknown key", "nope", http.StatusUnauthorized},
		// A read-only key is AUTHENTICATED and not authorized to write: 403, not 401,
		// because telling a valid credential it is invalid sends the operator to mint
		// a new key instead of widening the scope on the one they have.
		{"a read-only key", "read", http.StatusForbidden},
		{"a write-capable key", "admin", http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.key != "" {
				headers[auth.APIKeyHeader] = tc.key
			}
			rec := post(t, router, "/api/v1/intake?release_id=rel-1", `{"findings":[{"cve":"CVE-1"}]}`, headers)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

// --- the unwired door -------------------------------------------------------

// TestIntakeNotWired_RefusesHonestly — a node with no intake door says so rather than
// 404-ing or pretending to accept. A door that answers is a door a client will send a
// 60 MB SBOM through.
func TestIntakeNotWired_RefusesHonestly(t *testing.T) {
	h := evhttp.NewHandler(nil).Router()
	for _, call := range []struct {
		method, target string
	}{
		{http.MethodPost, "/intake?release_id=rel-1"},
		{http.MethodGet, "/intake/abc"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(call.method, call.target, strings.NewReader("{}")))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d, want 503", call.method, call.target, rec.Code)
		}
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}
