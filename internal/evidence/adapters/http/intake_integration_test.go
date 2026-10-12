//go:build integration

package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	evhttp "github.com/themis-project/themis/internal/evidence/adapters/http"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/adapters/wiring"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
)

// The slow path over real PostgreSQL and the REAL wiring — the converter ACL, the
// trust gate, the aggregate and the outbox all included. A fake-service test can
// prove the handler returns `202`; only this can prove the receipt reaches `filed`
// and the evidence is actually there afterwards, which is the whole of what `202`
// promises a client.

const (
	intakeRelease = "rel-intake-1"
	// intakeOtherRelease is a SECOND registered release, which exists for one
	// behaviour: byte-identical content aimed at it after it was filed against
	// intakeRelease must stay the loud `409 duplicate_other_release` (B6).
	intakeOtherRelease = "rel-intake-2"
)

var intakeDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		intakeDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "evidence-intake-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15545).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"shared_buffers": "128kB", "max_connections": "10"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping evidence intake integration tests: %v\n", err)
		os.Exit(0)
	}
	intakeDSN = "postgres://themis:themis@localhost:15545/themis?sslmode=disable"
	path, _ := filepath.Abs("../store/migrations")
	mig, err := migrate.New("file://"+path, intakeDSN)
	if err == nil {
		if upErr := mig.Up(); upErr != nil && !errors.Is(upErr, migrate.ErrNoChange) {
			err = upErr
		}
		_, _ = mig.Close()
	}
	if err != nil {
		_ = db.Stop()
		panic(err)
	}
	code := m.Run()
	_ = db.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// liveIntake wires the production composition over the test database. budget is the
// inline budget: a nanosecond forces every submission down the overflow path, which
// is how a slow estate is reproduced without a slow test.
//
// The allow-set stub stands in for the registry seam and knows TWO releases: most of
// these tests are about the slow path rather than about identity resolution, which has
// its own tests, but the cross-release duplicate of B6 needs a second release to be
// refused against.
func liveIntake(t *testing.T, budget time.Duration, knowledgeURL, governanceURL string) (http.Handler, *store.Store, *evhttp.Intake) {
	t.Helper()
	return liveIntakeWith(t, budget, knowledgeURL, governanceURL,
		subjectref.NewStub(intakeRelease, intakeOtherRelease), nil)
}

// liveIntakeWith is the same wiring with the registry seam supplied, so a test can
// exercise the {product, project, version} road and `create_release` — neither of which
// the allow-set stub can answer, because it knows ids and no names.
func liveIntakeWith(t *testing.T, budget time.Duration, knowledgeURL, governanceURL string,
	reg subjectref.Registry, prov app.ReleaseProvisioner) (http.Handler, *store.Store, *evhttp.Intake) {
	t.Helper()
	if intakeDSN == "" {
		t.Skip("no database")
	}
	pool, err := pgxpool.New(context.Background(), intakeDSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		"TRUNCATE intake_receipts, evidence_outbox, evidence RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	handler, st, intake := wiring.EvidenceAPI(wiring.Config{
		Pool:      pool,
		Registry:  reg,
		Provision: prov,
		Intake: evhttp.IntakeConfig{
			InlineBudget:  budget,
			KnowledgeURL:  knowledgeURL,
			GovernanceURL: governanceURL,
		},
	})
	t.Cleanup(func() {
		intake.Close()
		pool.Close()
	})
	return handler, st, intake
}

func submitIntake(t *testing.T, h http.Handler, query, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/intake?"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func readReceipt(t *testing.T, h http.Handler, intakeID string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/intake/"+intakeID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /intake/%s = %d: %s", intakeID, rec.Code, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	return out
}

// pollUntilTerminal reads the receipt until it leaves the ladder, exactly as the
// design's curl loop tells an operator to.
func pollUntilTerminal(t *testing.T, h http.Handler, intakeID string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		view := readReceipt(t, h, intakeID)
		switch view["status"] {
		case "filed", "rejected", "failed":
			return view
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("receipt %s never reached a terminal status", intakeID)
	return nil
}

// TestIntakeSlowPath_202ReachesFiledAndTheEvidenceIsThere — task 3.5's gate. The
// `202` is checked, and then the two things that make it a promise rather than an
// acknowledgement: the receipt advances on its own, and the document is readable at
// the id the receipt names.
func TestIntakeSlowPath_202ReachesFiledAndTheEvidenceIsThere(t *testing.T) {
	handler, st, _ := liveIntake(t, time.Nanosecond, "http://knowledge:8085", "http://governance:8083")
	ctx := context.Background()

	sbom, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx.json"))
	if err != nil {
		t.Fatalf("read the SBOM fixture: %v", err)
	}

	// Step 1 — the SBOM, first (D6).
	rec := submitIntake(t, handler, "release_id="+intakeRelease, "application/json", string(sbom))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("SBOM status = %d, want 202: %s", rec.Code, rec.Body)
	}
	var accepted map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted["status"] != "accepted" {
		t.Errorf("status = %v, want accepted", accepted["status"])
	}
	if accepted["evidence_id"] != nil {
		t.Errorf("a 202 names evidence it has not filed: %v", accepted["evidence_id"])
	}
	sbomIntakeID, _ := accepted["intake_id"].(string)

	filedSBOM := pollUntilTerminal(t, handler, sbomIntakeID)
	if filedSBOM["status"] != "filed" {
		t.Fatalf("SBOM receipt = %v", filedSBOM)
	}
	sbomEvidenceID, _ := filedSBOM["evidence_id"].(string)
	if sbomEvidenceID == "" {
		t.Fatal("a filed receipt names no evidence")
	}
	if got, err := st.GetByID(ctx, domain.EvidenceID(sbomEvidenceID)); err != nil {
		t.Errorf("the evidence the receipt names is not in the store: %v", err)
	} else if got.Kind() != domain.KindSBOM || got.Subject().ReleaseID != intakeRelease {
		t.Errorf("filed evidence = %s / %s", got.Kind(), got.Subject().ReleaseID)
	}
	if comps, _ := filedSBOM["components"].(float64); comps < 1 {
		t.Errorf("components = %v, want the count the inventory actually carries", filedSBOM["components"])
	}
	// An SBOM has no scanner report to ask about, so only the posture check applies.
	assertNextChecks(t, filedSBOM, []string{"posture"})

	// Step 2 — the vulnerability report, second. The SBOM above is its inventory, so
	// no override is needed.
	report := fmt.Sprintf(`{"findings":[{"cve":"CVE-2024-2961","observed_at":%q,"severity":"high","component":{"purl":"pkg:deb/debian/openssl@3.0.11","name":"openssl","version":"3.0.11","ecosystem":"deb"}}]}`,
		time.Date(2026, 9, 29, 7, 23, 22, 0, time.UTC).Format(time.RFC3339))
	rec = submitIntake(t, handler, "release_id="+intakeRelease+"&provenance_source=cortex", "application/json", report)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("report status = %d, want 202: %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	reportIntakeID, _ := accepted["intake_id"].(string)

	filedReport := pollUntilTerminal(t, handler, reportIntakeID)
	if filedReport["status"] != "filed" {
		t.Fatalf("report receipt = %v", filedReport)
	}
	if filedReport["detected_kind"] != "vuln-report" || filedReport["detected_format"] != "curated" {
		t.Errorf("detected %v / %v", filedReport["detected_kind"], filedReport["detected_format"])
	}
	if total, _ := filedReport["findings_total"].(float64); total != 1 {
		t.Errorf("findings_total = %v, want 1", filedReport["findings_total"])
	}
	if digest, _ := filedReport["source_digest"].(string); len(digest) != 64 {
		t.Errorf("source_digest = %q, want a lowercase-hex SHA-256 of the submitted bytes", digest)
	}
	reportEvidenceID, _ := filedReport["evidence_id"].(string)
	if kind, doc, err := st.GetRawDocument(ctx, domain.EvidenceID(reportEvidenceID)); err != nil {
		t.Errorf("the filed report is not in the store: %v", err)
	} else if kind != string(domain.KindScannerReport) || !strings.Contains(string(doc), "CVE-2024-2961") {
		t.Errorf("filed report = %s / %s", kind, doc)
	}
	// Both checks now: Knowledge answers what the report left unresolved, Governance
	// answers the release's posture. The receipt is terminal at `filed` and claims
	// neither (D10).
	assertNextChecks(t, filedReport, []string{"unresolved", "posture"})
}

// TestIntake_RefusalLeavesAReceiptAndNoEvidence — D13 over a real database: stages
// 1-6 are side-effect-free, so a refused intake writes a receipt and nothing else.
// No evidence row, and therefore no outbox note and no bus traffic.
func TestIntake_RefusalLeavesAReceiptAndNoEvidence(t *testing.T) {
	handler, st, _ := liveIntake(t, 5*time.Second, "", "")
	ctx := context.Background()

	// The 2026-10-05 body: a bare JSON array of vendor records. It passed
	// `json.Valid`, was filed unreadable through the old door, and halted
	// Knowledge's evidence stream for 31 hours.
	rec := submitIntake(t, handler, "release_id="+intakeRelease, "application/json",
		`[{"asset_name":"oamp","package_purl":"pkg:rpm/redhat/zlib@1.2.11"}]`)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415 (the body matches no dialect): %s", rec.Code, rec.Body)
	}
	var problem map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem["reason"] != "unrecognised_format" {
		t.Errorf("reason = %v", problem["reason"])
	}
	intakeID, _ := problem["intake_id"].(string)
	if intakeID == "" {
		t.Fatal("the refusal names no receipt")
	}

	view := readReceipt(t, handler, intakeID)
	if view["status"] != "rejected" || view["reason"] != "unrecognised_format" {
		t.Errorf("receipt = %v", view)
	}
	if _, present := view["next_checks"]; present {
		t.Error("a refused receipt carries next_checks; nothing landed to check on")
	}

	if list, err := st.ListByRelease(ctx, intakeRelease); err != nil {
		t.Fatal(err)
	} else if len(list) != 0 {
		t.Errorf("%d evidence rows after a refusal, want 0", len(list))
	}
}

// TestIntake_NoInventoryForTheReleaseIsRefusedAndOverridable — D6, including the
// deliberate override being recorded rather than merely allowed.
func TestIntake_NoInventoryForTheReleaseIsRefusedAndOverridable(t *testing.T) {
	handler, _, _ := liveIntake(t, 5*time.Second, "", "")
	report := fmt.Sprintf(`{"findings":[{"cve":"CVE-2023-45853","observed_at":%q,"component":{"purl":"pkg:deb/debian/zlib@1.3","name":"zlib","version":"1.3","ecosystem":"deb"}}]}`,
		time.Date(2026, 9, 29, 7, 23, 22, 0, time.UTC).Format(time.RFC3339))

	rec := submitIntake(t, handler, "release_id="+intakeRelease, "application/json", report)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body)
	}
	var problem map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem["reason"] != "no_inventory_for_release" {
		t.Fatalf("reason = %v", problem["reason"])
	}
	if detail, _ := problem["detail"].(string); !strings.Contains(detail, "allow_without_sbom") {
		t.Errorf("detail %q does not say how to proceed", detail)
	}

	rec = submitIntake(t, handler, "release_id="+intakeRelease+"&allow_without_sbom=true", "application/json", report)
	if rec.Code != http.StatusCreated {
		t.Fatalf("override status = %d, want 201: %s", rec.Code, rec.Body)
	}
}

// TestIntakeStartupRecovery_ClosesOutWhatARestartInterrupted — a receipt stuck
// non-terminal would have a client polling a goroutine that no longer exists, and
// only the NEXT process can tell. Terminal receipts are left exactly as they are.
func TestIntakeStartupRecovery_ClosesOutWhatARestartInterrupted(t *testing.T) {
	handler, st, intake := liveIntake(t, 5*time.Second, "", "")
	ctx := context.Background()

	for _, seed := range []store.IntakeReceipt{
		{IntakeID: "crashed", Status: domain.ReceiptConverting, ReleaseID: intakeRelease, Detail: "original"},
		{IntakeID: "finished", Status: domain.ReceiptFiled, EvidenceID: "ev-x", Detail: "original"},
	} {
		if err := st.SaveIntakeReceipt(ctx, seed); err != nil {
			t.Fatal(err)
		}
	}
	// Age both past the inline budget: anything younger could still be in flight.
	if _, err := st.PurgeExpiredReceipts(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, intakeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `UPDATE intake_receipts SET created_at = created_at - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}

	n, err := intake.RecoverInterruptedReceipts(ctx)
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if n != 1 {
		t.Errorf("recovered %d, want 1", n)
	}

	crashed := readReceipt(t, handler, "crashed")
	if crashed["status"] != "failed" {
		t.Errorf("status = %v, want failed", crashed["status"])
	}
	if detail, _ := crashed["detail"].(string); detail != "interrupted by restart; resubmit" {
		t.Errorf("detail = %q, want it to name the action", detail)
	}
	if crashed["reason"] != nil {
		t.Errorf("reason = %v; a failure is a statement about Themis and names none", crashed["reason"])
	}

	if finished := readReceipt(t, handler, "finished"); finished["detail"] != "original" {
		t.Errorf("a terminal receipt was rewritten: %v", finished)
	}
}

// --- `build_id`: provenance, echoed, and inert (EDR-INTAKE-01 B5) -----------

// TestBuildIDIsEchoedOnTheReceiptAndStoredOnTheEvidence — B5's two destinations, over
// the real wiring because they are two different stores: `build_id` becomes artifact
// provenance on the EVIDENCE row (`provenance_build_id`) and is echoed on the RECEIPT,
// on both of the receipt's surfaces — the synchronous answer and
// `GET /intake/{intake_id}`, which is why 2.3 gives the receipt its own column.
//
// Asserted verbatim: refusing an out-of-bound value rather than truncating it is only
// worth anything if what is stored is the value the caller recorded.
func TestBuildIDIsEchoedOnTheReceiptAndStoredOnTheEvidence(t *testing.T) {
	handler, st, _ := liveIntake(t, 5*time.Second, "", "")
	ctx := context.Background()

	const buildID = "Jenkins/OAMP-core/1917"
	posted := submitSBOM(t, handler, "release_id="+intakeRelease+"&build_id="+url.QueryEscape(buildID),
		sbomFixture(t, "cyclonedx.json"), http.StatusCreated)

	if got, _ := posted["build_id"].(string); got != buildID {
		t.Errorf("the POST receipt echoes build_id = %q, want %q", got, buildID)
	}
	intakeID, _ := posted["intake_id"].(string)
	if got, _ := readReceipt(t, handler, intakeID)["build_id"].(string); got != buildID {
		t.Errorf("GET /intake/%s echoes build_id = %q, want %q", intakeID, got, buildID)
	}

	evidenceID, _ := posted["evidence_id"].(string)
	filed, err := st.GetByID(ctx, domain.EvidenceID(evidenceID))
	if err != nil {
		t.Fatalf("the evidence the receipt names is not in the store: %v", err)
	}
	if got := filed.Provenance().BuildID; got != buildID {
		t.Errorf("filed provenance build id = %q, want %q", got, buildID)
	}
}

// TestTwoSubmissionsDifferingOnlyInBuildIDFileOneEvidenceRow — B5's inertness, which is
// the decision and not an omission: `build_id` takes no part in dedup, so the same
// curated bytes from two pipeline runs are ONE document (D3/D8), not two.
//
// A build id that influenced dedup would turn two genuinely identical documents into two
// evidence rows, and the release's history would then count builds instead of documents.
func TestTwoSubmissionsDifferingOnlyInBuildIDFileOneEvidenceRow(t *testing.T) {
	handler, st, _ := liveIntake(t, 5*time.Second, "", "")
	ctx := context.Background()
	sbom := sbomFixture(t, "cyclonedx.json")

	first := submitSBOM(t, handler, "release_id="+intakeRelease+"&build_id=first-run", sbom, http.StatusCreated)
	if created, _ := first["created"].(bool); !created {
		t.Errorf("created = %v on the first submission, want true", first["created"])
	}
	// 200, not 201: this request created nothing. The ONLY difference between the two
	// requests is the build id.
	retry := submitSBOM(t, handler, "release_id="+intakeRelease+"&build_id=retry-run", sbom, http.StatusOK)
	if created, _ := retry["created"].(bool); created {
		t.Error("created = true on a byte-identical retry; dedup was disturbed by the build id")
	}
	if first["evidence_id"] != retry["evidence_id"] {
		t.Errorf("evidence ids %v and %v, want the retry to resolve to the first document",
			first["evidence_id"], retry["evidence_id"])
	}

	rows, err := st.ListByRelease(ctx, intakeRelease)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("%d evidence rows for the release, want 1 — `build_id` is not part of the dedup key", len(rows))
	}
}

// TestDedupKeepsTheFirstBuildIDAndTheRetryReceiptCarriesItsOwn — the one place
// `build_id` can look broken, asserted as the design it is (B5, design §6).
//
// A receipt records an ATTEMPT and the evidence row records what was FILED. A
// byte-identical retry files nothing, so the document keeps the FIRST run's build id —
// evidence is immutable (CON-0007), and an `ON CONFLICT … DO NOTHING` write does not
// rewrite the first upload's provenance — while the retry's own value appears on its own
// receipt. The two therefore DIFFER, and that is asserted explicitly: a future
// "improvement" that made them agree would have to either rewrite filed provenance or
// drop what the second caller told us.
func TestDedupKeepsTheFirstBuildIDAndTheRetryReceiptCarriesItsOwn(t *testing.T) {
	handler, st, _ := liveIntake(t, 5*time.Second, "", "")
	ctx := context.Background()
	sbom := sbomFixture(t, "cyclonedx.json")

	const firstBuild, retryBuild = "Jenkins/OAMP-core/1917", "Jenkins/OAMP-core/1918"
	first := submitSBOM(t, handler, "release_id="+intakeRelease+"&build_id="+firstBuild, sbom, http.StatusCreated)
	retry := submitSBOM(t, handler, "release_id="+intakeRelease+"&build_id="+retryBuild, sbom, http.StatusOK)

	evidenceID, _ := first["evidence_id"].(string)
	filed, err := st.GetByID(ctx, domain.EvidenceID(evidenceID))
	if err != nil {
		t.Fatalf("get the filed document: %v", err)
	}
	if got := filed.Provenance().BuildID; got != firstBuild {
		t.Errorf("the filed document's build id = %q, want the FIRST upload's %q", got, firstBuild)
	}
	gotRetry, _ := retry["build_id"].(string)
	if gotRetry != retryBuild {
		t.Errorf("the retry's receipt reports build_id = %q, want its own %q", gotRetry, retryBuild)
	}
	retryIntakeID, _ := retry["intake_id"].(string)
	if got, _ := readReceipt(t, handler, retryIntakeID)["build_id"].(string); got != retryBuild {
		t.Errorf("the retry's stored receipt reports build_id = %q, want its own %q", got, retryBuild)
	}
	if filed.Provenance().BuildID == gotRetry {
		t.Error("the filed document and the retry's receipt report the same build id; " +
			"a receipt records an attempt and the evidence row records what was filed, and on a dedup those are two different runs")
	}
}

// --- B6: the behaviours this change does NOT touch --------------------------

// TestByteIdenticalContentOnAnotherReleaseIsStill409 — B6, unchanged (D8,
// EDR-EVIDENCE-01 D3). Byte-identical content aimed at a DIFFERENT release stays a loud
// refusal: the second release received nothing, and answering `200` with the other
// release's evidence id read as success on this estate once already (measured live
// 2026-08-19).
func TestByteIdenticalContentOnAnotherReleaseIsStill409(t *testing.T) {
	handler, st, _ := liveIntake(t, 5*time.Second, "", "")
	ctx := context.Background()
	sbom := sbomFixture(t, "cyclonedx.json")

	first := submitSBOM(t, handler, "release_id="+intakeRelease, sbom, http.StatusCreated)

	rec := submitIntake(t, handler, "release_id="+intakeOtherRelease, "application/json", string(sbom))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body)
	}
	var problem map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem["reason"] != "duplicate_other_release" {
		t.Errorf("reason = %v, want duplicate_other_release", problem["reason"])
	}
	// The refusal names where the content already lives, which is what makes it
	// actionable rather than merely a rejection.
	if detail, _ := problem["detail"].(string); !strings.Contains(detail, intakeRelease) {
		t.Errorf("detail %q does not name the release the content is filed against", detail)
	}
	if rows, err := st.ListByRelease(ctx, intakeOtherRelease); err != nil {
		t.Fatal(err)
	} else if len(rows) != 0 {
		t.Errorf("%d evidence rows on the refused release, want 0", len(rows))
	}
	if rows, err := st.ListByRelease(ctx, intakeRelease); err != nil {
		t.Fatal(err)
	} else if len(rows) != 1 || string(rows[0].ID) != first["evidence_id"] {
		t.Errorf("the original release's evidence changed: %+v", rows)
	}
}

// TestADifferentSBOMForTheSameReleaseIsFiledAsNewHistory — B6, and not a convenience:
// **EDR-DELIVERY-01 M2-5 rests on it.** Its rebuild baseline is "the immediately-previous
// SBOM of the SAME Release, by upload order", so a release that keeps its successive
// SBOMs is the precondition for the rebuild loop being able to say whether a rebuild
// closed anything. A newer SBOM therefore adds history and REPLACES nothing — both rows
// are retained.
func TestADifferentSBOMForTheSameReleaseIsFiledAsNewHistory(t *testing.T) {
	handler, st, _ := liveIntake(t, 5*time.Second, "", "")
	ctx := context.Background()

	first := submitSBOM(t, handler, "release_id="+intakeRelease, sbomFixture(t, "cyclonedx.json"), http.StatusCreated)
	second := submitSBOM(t, handler, "release_id="+intakeRelease, sbomFixture(t, "spdx.json"), http.StatusCreated)

	if first["evidence_id"] == second["evidence_id"] {
		t.Fatalf("both SBOMs resolved to one document %v; a different document is new history, not a dedup", first["evidence_id"])
	}
	rows, err := st.ListByRelease(ctx, intakeRelease)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d evidence rows after two different SBOMs, want 2 — M2-5's baseline is the PREVIOUS SBOM of this release", len(rows))
	}
	ids := map[string]bool{string(rows[0].ID): true, string(rows[1].ID): true}
	for _, want := range []any{first["evidence_id"], second["evidence_id"]} {
		id, _ := want.(string)
		if !ids[id] {
			t.Errorf("evidence %q is no longer on the release; a newer SBOM replaced it instead of joining it", id)
		}
	}
}

// TestSBOMBeforeReportStillEnforced — D6, unchanged by `create_release` (B6), including
// the case the new parameter creates: a brand-new VERSION.
//
// Two halves, and the first is the one that matters. A report for a version that does not
// exist yet is refused BEFORE the create, so a bot that sends its report first leaves no
// empty Release behind — the provisioner is asserted UNCALLED, which is what makes
// "nothing is created on any refusal" (B2/B3) true of the only step that writes into
// Registry. The second half is D6's existing `allow_without_sbom` override, which still
// works and now also creates the version it was given.
//
// The release_id road's halves of D6 are TestIntake_NoInventoryForTheReleaseIsRefusedAndOverridable
// above; this test is the name road, which is the one `create_release` added.
func TestSBOMBeforeReportStillEnforced(t *testing.T) {
	// The auth tests' fake estate, reused: it is the one read seam in this package that
	// knows NAMES (the allow-set stub answers every name lookup with "nothing", so no
	// triple resolves far enough for `create_release` to reach the create), and
	// `fxNewVersion` is a version it deliberately does not hold.
	prov := &countingProvisioner{}
	reg := provisionedRegistry{authRegistry: &authRegistry{}, prov: prov}
	handler, st, _ := liveIntakeWith(t, 5*time.Second, "", "", reg, prov)
	ctx := context.Background()

	const version = fxNewVersion
	query := "product=" + fxProduct + "&project=" + fxProject + "&version=" + version + "&create_release=true"
	report := curatedReport()

	rec := submitIntake(t, handler, query, "application/json", report)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body)
	}
	var problem map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem["reason"] != "no_inventory_for_release" {
		t.Fatalf("reason = %v, want no_inventory_for_release", problem["reason"])
	}
	// The detail names the VERSION, because there is no release id to name yet — "release
	// '' has no inventory" is the shape that sends an operator hunting.
	if detail, _ := problem["detail"].(string); !strings.Contains(detail, version) || !strings.Contains(detail, "allow_without_sbom") {
		t.Errorf("detail = %q; it must name the version and what to do about it", detail)
	}
	if prov.calls != 0 {
		t.Errorf("find-or-create ran %d time(s) for a refused report; nothing is created on a refusal", prov.calls)
	}

	// The override, which D6 has always had: the caller states that the findings rest on
	// no inventory, and the version is then created — once — immediately before filing.
	rec = submitIntake(t, handler, query+"&allow_without_sbom=true", "application/json", report)
	if rec.Code != http.StatusCreated {
		t.Fatalf("override status = %d, want 201: %s", rec.Code, rec.Body)
	}
	var receipt map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if prov.calls != 1 {
		t.Fatalf("find-or-create ran %d time(s), want exactly once", prov.calls)
	}
	if prov.gotVersion != version {
		t.Errorf("created version %q, want the submitted %q — Themis never corrects a version it was given", prov.gotVersion, version)
	}
	created := fxNewRelease
	if got, _ := receipt["release_id"].(string); got != created {
		t.Errorf("the receipt names release %q, want the created %q", got, created)
	}
	rows, err := st.ListByRelease(ctx, created)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("%d evidence rows on the created release, want the report", len(rows))
	}
}

// --- fixtures and seams for the tests above ---------------------------------

// submitSBOM posts an SBOM, asserts the status and returns the decoded receipt. The
// status is a parameter rather than asserted by the caller because these tests turn on
// the difference between `201` and `200` — filed versus deduped — and a helper that
// accepted either would hide the thing being tested.
func submitSBOM(t *testing.T, h http.Handler, query string, body []byte, want int) map[string]any {
	t.Helper()
	rec := submitIntake(t, h, query, "application/json", string(body))
	if rec.Code != want {
		t.Fatalf("status = %d, want %d: %s", rec.Code, want, rec.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode receipt from %s: %v", rec.Body.String(), err)
	}
	return out
}

// provisionedRegistry is the auth fixture's read seam plus the one thing a real Registry
// does that a map of fixed names cannot: a version that was just CREATED exists
// afterwards. Filing re-validates the subject release through this same seam
// (EDR-KERNEL-01 D1), so without it the create would succeed and the file would then
// refuse a release Themis had made one line earlier.
type provisionedRegistry struct {
	*authRegistry
	prov *countingProvisioner
}

func (r provisionedRegistry) ReleaseExists(ctx context.Context, releaseID string) (bool, error) {
	if releaseID == fxNewRelease && r.prov.calls > 0 {
		return true, nil
	}
	return r.authRegistry.ReleaseExists(ctx, releaseID)
}

func sbomFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", name))
	if err != nil {
		t.Fatalf("read the %s fixture: %v", name, err)
	}
	return raw
}

// curatedReport is one curated finding, with an `observed_at` the caller asserts — the
// door refuses a timestamp it cannot believe, and derives nothing from the upload time.
func curatedReport() string {
	return fmt.Sprintf(`{"findings":[{"cve":"CVE-2023-45853","observed_at":%q,"severity":"high","component":{"purl":"pkg:deb/debian/zlib@1.3","name":"zlib","version":"1.3","ecosystem":"deb"}}]}`,
		time.Date(2026, 9, 29, 7, 23, 22, 0, time.UTC).Format(time.RFC3339))
}

func assertNextChecks(t *testing.T, view map[string]any, want []string) {
	t.Helper()
	raw, ok := view["next_checks"].([]any)
	if !ok {
		t.Fatalf("next_checks = %v, want %v", view["next_checks"], want)
	}
	if len(raw) != len(want) {
		t.Fatalf("next_checks = %v, want %v", raw, want)
	}
	for i, entry := range raw {
		check, _ := entry.(map[string]any)
		if check["what"] != want[i] {
			t.Errorf("next_checks[%d].what = %v, want %q", i, check["what"], want[i])
		}
		if url, _ := check["url"].(string); !strings.HasPrefix(url, "http://") {
			t.Errorf("next_checks[%d].url = %q", i, url)
		}
	}
}
