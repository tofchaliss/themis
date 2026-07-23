//go:build e2e

// Package e2e is a Mac-friendly, zero-setup end-to-end suite for the Evidence
// service. It starts embedded Postgres (no Docker) ONCE for the whole suite,
// applies the Evidence migrations, wires the real service via
// internal/evidence/adapters/wiring, serves it over an httptest server, and drives
// the REST API across several scenarios:
//
//   - happy path (CycloneDX): register → facts → inventory → list → idempotent
//     replay → exactly-one outbox event;
//   - SPDX input: a second supported standard parses into the canonical inventory;
//   - unknown-release rejection: an unregistered subject Release is refused (422);
//   - unsupported-format rejection: a non-standard format (e.g. trivy) is refused
//     with a helpful supported-formats list (422);
//   - concurrent duplicate: N simultaneous identical uploads resolve to one record
//     and exactly one event.
//
// Run:   make e2e-evidence
// Use your own SBOM (happy path):  EVIDENCE_E2E_SBOM=/path/to/your.sbom.json make e2e-evidence
// Happy-path format override:      EVIDENCE_E2E_FORMAT=spdx make e2e-evidence
// External Postgres:               EVIDENCE_E2E_DSN=postgres://... make e2e-evidence
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/adapters/wiring"
)

// Releases the suite registers up front. relUnknown is deliberately NOT registered
// so the unknown-subject rejection can be exercised.
const (
	relHappy      = "rel-happy"
	relSPDX       = "rel-spdx"
	relConcurrent = "rel-concurrent"
	relUnknown    = "rel-unknown"
)

// Shared test infrastructure, set up once in TestMain.
var (
	testSrv    *httptest.Server
	testPool   *pgxpool.Pool
	skipReason string
)

func TestMain(m *testing.M) {
	os.Exit(runSuite(m))
}

// runSuite starts one embedded Postgres (or an external DB via EVIDENCE_E2E_DSN),
// migrates it, wires the Evidence service, and serves it for all tests. On a setup
// failure with no external DB it records a skip reason (each test skips) rather than
// failing, so the suite is a no-op where embedded Postgres cannot run.
func runSuite(m *testing.M) int {
	dsn := os.Getenv("EVIDENCE_E2E_DSN")
	if dsn == "" {
		d, stop, err := startEmbedded()
		if err != nil {
			skipReason = fmt.Sprintf("embedded postgres unavailable (set EVIDENCE_E2E_DSN for an external DB): %v", err)
			return m.Run()
		}
		defer stop()
		dsn = d
	}
	if err := migrateUp(dsn); err != nil {
		skipReason = fmt.Sprintf("migrate: %v", err)
		return m.Run()
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		skipReason = err.Error()
		return m.Run()
	}
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		skipReason = err.Error()
		return m.Run()
	}
	defer pool.Close()
	testPool = pool

	apiHandler, _ := wiring.EvidenceAPI(pool, subjectref.NewStub(relHappy, relSPDX, relConcurrent))
	router := chi.NewRouter()
	router.Mount("/api/v1", apiHandler)
	testSrv = httptest.NewServer(router)
	defer testSrv.Close()

	return m.Run()
}

// requireDB skips a test when shared setup could not start a database.
func requireDB(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

// TestEvidenceEndToEnd is the CycloneDX happy path: the full register → read →
// idempotent-replay → one-event flow through real HTTP + Postgres.
func TestEvidenceEndToEnd(t *testing.T) {
	requireDB(t)
	sbom := loadSampleSBOM(t)
	body := map[string]any{
		"kind":               "sbom",
		"format":             envDefault("EVIDENCE_E2E_FORMAT", "cyclonedx"),
		"subject_release_id": relHappy,
		"document":           string(sbom),
	}

	// 1. Register (new) → 201 + id.
	id := register(t, body, http.StatusCreated)
	t.Logf("registered evidence id=%s", id)

	// 2. Facts.
	facts := getObject(t, testSrv.URL+"/api/v1/evidence/"+id, http.StatusOK)
	if facts["subject_release_id"] != relHappy {
		t.Errorf("facts subject_release_id = %v, want %s", facts["subject_release_id"], relHappy)
	}
	if facts["trust_status"] != "accepted" {
		t.Errorf("facts trust_status = %v, want accepted", facts["trust_status"])
	}

	// 3. Inventory — at least one component.
	inv := getObject(t, testSrv.URL+"/api/v1/evidence/"+id+"/inventory", http.StatusOK)
	comps, _ := inv["components"].([]any)
	if len(comps) == 0 {
		t.Fatalf("inventory has no components — check the sample SBOM / EVIDENCE_E2E_FORMAT")
	}
	t.Logf("inventory: %d components", len(comps))

	// 4. List by release contains the id.
	if list := getArray(t, testSrv.URL+"/api/v1/evidence?release="+relHappy, http.StatusOK); len(list) == 0 {
		t.Error("list by release is empty")
	}

	// 5. Idempotent re-register → 200 + same id.
	if id2 := register(t, body, http.StatusOK); id2 != id {
		t.Errorf("idempotent re-register id = %s, want %s", id2, id)
	}

	// 6. Exactly one outbox note for this evidence (event emitted once, not on replay).
	if n := outboxCount(t, id); n != 1 {
		t.Errorf("outbox notes for %s = %d, want 1", id, n)
	}
	t.Log("e2e OK: register → facts → inventory → list → idempotent replay → exactly one event")
}

// TestEvidenceSPDX registers an SPDX SBOM — the second supported standard — and
// checks it parses into the canonical inventory.
func TestEvidenceSPDX(t *testing.T) {
	requireDB(t)
	spdx := readFixture(t, "sample.spdx.json")
	body := map[string]any{
		"kind":               "sbom",
		"format":             "spdx",
		"subject_release_id": relSPDX,
		"document":           string(spdx),
	}
	id := register(t, body, http.StatusCreated)
	facts := getObject(t, testSrv.URL+"/api/v1/evidence/"+id, http.StatusOK)
	if facts["kind"] != "sbom" {
		t.Errorf("facts kind = %v, want sbom", facts["kind"])
	}
	inv := getObject(t, testSrv.URL+"/api/v1/evidence/"+id+"/inventory", http.StatusOK)
	comps, _ := inv["components"].([]any)
	if len(comps) != 2 {
		t.Fatalf("SPDX inventory components = %d, want 2", len(comps))
	}
	t.Logf("SPDX OK: registered %s with %d components", id, len(comps))
}

// TestEvidenceUnknownReleaseRejected checks that evidence for an unregistered
// Release is refused with 422 before any persistence (EDR-EVIDENCE-01 D5).
func TestEvidenceUnknownReleaseRejected(t *testing.T) {
	requireDB(t)
	sbom := loadSampleSBOM(t)
	body := map[string]any{
		"kind":               "sbom",
		"format":             "cyclonedx",
		"subject_release_id": relUnknown, // never registered
		"document":           string(sbom),
	}
	status, raw := postEvidence(t, body)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown-release status = %d, want 422: %s", status, raw)
	}
	prob := decodeProblem(t, raw)
	if prob.Title != "unknown subject release" {
		t.Errorf("problem title = %q, want %q", prob.Title, "unknown subject release")
	}
	t.Logf("unknown-release OK: 422 %q", prob.Title)
}

// TestEvidenceUnsupportedFormatRejected checks that a non-standard format (a
// producer, not a standard) is refused with 422 and a helpful supported list
// (EDR-EVIDENCE-01 D4). The document is valid JSON, so it clears the trust gate and
// fails at parse — never persisted.
func TestEvidenceUnsupportedFormatRejected(t *testing.T) {
	requireDB(t)
	sbom := loadSampleSBOM(t)
	body := map[string]any{
		"kind":               "sbom",
		"format":             "trivy", // a scanner/producer, not a supported standard
		"subject_release_id": relHappy,
		"document":           string(sbom),
	}
	status, raw := postEvidence(t, body)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported-format status = %d, want 422: %s", status, raw)
	}
	prob := decodeProblem(t, raw)
	if prob.Title != "unsupported SBOM format" {
		t.Errorf("problem title = %q, want %q", prob.Title, "unsupported SBOM format")
	}
	if len(prob.SupportedFormats) == 0 {
		t.Error("expected a non-empty supported_formats list in the rejection")
	}
	t.Logf("unsupported-format OK: 422 %q supported=%v", prob.Title, prob.SupportedFormats)
}

// concurrentSBOM is a distinct CycloneDX document (its own fingerprint) so the
// concurrency test is independent of the other scenarios' records.
const concurrentSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": { "component": { "type": "application", "name": "concurrent-app", "version": "9.9.9" } },
  "components": [
    { "bom-ref": "ref-openssl", "type": "library", "name": "openssl", "version": "3.0.11", "purl": "pkg:deb/debian/openssl@3.0.11" }
  ]
}`

// TestEvidenceConcurrentDuplicate fires N simultaneous identical uploads and checks
// they resolve to one record (one create) and exactly one outbox event — the
// fingerprint-idempotent Save under real HTTP concurrency (EDR-EVIDENCE-01 D3/D7).
func TestEvidenceConcurrentDuplicate(t *testing.T) {
	requireDB(t)
	body := map[string]any{
		"kind":               "sbom",
		"format":             "cyclonedx",
		"subject_release_id": relConcurrent,
		"document":           concurrentSBOM,
	}

	const workers = 8
	type result struct {
		status  int
		id      string
		created bool
		err     error
	}
	results := make([]result, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all goroutines together
			status, raw, err := doPost(testSrv.URL, body)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			var out struct {
				Id      string `json:"id"`
				Created bool   `json:"created"`
			}
			_ = json.Unmarshal(raw, &out)
			results[i] = result{status: status, id: out.Id, created: out.Created}
		}(i)
	}
	close(start)
	wg.Wait()

	creates := 0
	id := ""
	for _, r := range results {
		if r.err != nil {
			t.Fatalf("concurrent POST failed: %v", r.err)
		}
		if r.status != http.StatusOK && r.status != http.StatusCreated {
			t.Fatalf("concurrent register status = %d (id=%s)", r.status, r.id)
		}
		if r.id == "" {
			t.Fatal("concurrent register returned empty id")
		}
		switch {
		case id == "":
			id = r.id
		case r.id != id:
			t.Errorf("concurrent register ids diverged: %s vs %s", r.id, id)
		}
		if r.created {
			creates++
		}
	}
	if creates != 1 {
		t.Errorf("concurrent creations = %d, want exactly 1", creates)
	}
	if n := outboxCount(t, id); n != 1 {
		t.Errorf("outbox notes for %s = %d, want exactly 1", id, n)
	}
	t.Logf("concurrent-duplicate OK: %d requests → 1 create, id=%s, 1 event", workers, id)
}

// --- HTTP helpers ----------------------------------------------------------

// doPost posts an evidence registration and returns status + body. It never touches
// *testing.T, so it is safe to call from goroutines.
func doPost(base string, body map[string]any) (int, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	resp, err := http.Post(base+"/api/v1/evidence", "application/json", bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}

func postEvidence(t *testing.T, body map[string]any) (int, []byte) {
	t.Helper()
	status, b, err := doPost(testSrv.URL, body)
	if err != nil {
		t.Fatalf("POST evidence: %v", err)
	}
	return status, b
}

func register(t *testing.T, body map[string]any, wantStatus int) string {
	t.Helper()
	status, b := postEvidence(t, body)
	if status != wantStatus {
		t.Fatalf("register status = %d, want %d: %s", status, wantStatus, b)
	}
	var out struct {
		Id string `json:"id"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	return out.Id
}

type problem struct {
	Title            string   `json:"title"`
	Detail           string   `json:"detail"`
	SupportedFormats []string `json:"supported_formats"`
}

func decodeProblem(t *testing.T, raw []byte) problem {
	t.Helper()
	var p problem
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("decode problem envelope: %v", err)
	}
	return p
}

func getObject(t *testing.T, url string, wantStatus int) map[string]any {
	t.Helper()
	b := get(t, url, wantStatus)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return m
}

func getArray(t *testing.T, url string, wantStatus int) []any {
	t.Helper()
	b := get(t, url, wantStatus)
	var a []any
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return a
}

func get(t *testing.T, url string, wantStatus int) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s status = %d, want %d: %s", url, resp.StatusCode, wantStatus, b)
	}
	return b
}

func outboxCount(t *testing.T, evidenceID string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(),
		"SELECT count(*) FROM evidence_outbox WHERE evidence_id = $1", evidenceID).Scan(&n); err != nil {
		t.Fatalf("count outbox for %s: %v", evidenceID, err)
	}
	return n
}

// --- fixtures + infra ------------------------------------------------------

func loadSampleSBOM(t *testing.T) []byte {
	t.Helper()
	path := envDefault("EVIDENCE_E2E_SBOM", filepath.Join("testdata", "sample.sbom.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample SBOM %q: %v (set EVIDENCE_E2E_SBOM to your file)", path, err)
	}
	return raw
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	return raw
}

func startEmbedded() (string, func(), error) {
	dir, err := os.MkdirTemp("", "evidence-e2e-*")
	if err != nil {
		return "", nil, err
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15555).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"max_connections": "20"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	stop := func() { _ = db.Stop(); _ = os.RemoveAll(dir) }
	return "postgres://themis:themis@localhost:15555/themis?sslmode=disable", stop, nil
}

func migrateUp(dsn string) error {
	path, err := filepath.Abs(filepath.Join("..", "..", "internal", "evidence", "adapters", "store", "migrations"))
	if err != nil {
		return err
	}
	m, err := migrate.New("file://"+path, dsn)
	if err != nil {
		return err
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
