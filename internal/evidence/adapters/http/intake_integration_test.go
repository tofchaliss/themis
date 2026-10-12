//go:build integration

package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	"github.com/themis-project/themis/internal/evidence/domain"
)

// The slow path over real PostgreSQL and the REAL wiring — the converter ACL, the
// trust gate, the aggregate and the outbox all included. A fake-service test can
// prove the handler returns `202`; only this can prove the receipt reaches `filed`
// and the evidence is actually there afterwards, which is the whole of what `202`
// promises a client.

const intakeRelease = "rel-intake-1"

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
func liveIntake(t *testing.T, budget time.Duration, knowledgeURL, governanceURL string) (http.Handler, *store.Store, *evhttp.Intake) {
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
		Pool: pool,
		// The allow-set stub stands in for the registry seam: this test is about the
		// slow path, not about identity resolution, which has its own tests.
		Registry: subjectref.NewStub(intakeRelease),
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
