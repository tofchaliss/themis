//go:build e2e

// Package pipeline holds the in-process composed pipeline runner (EB-08, dev/e2e only): it
// wires all four bounded contexts against ONE PostgreSQL server with a database per context
// plus the dedicated `bus` database, drives them through the platform event bus, and lets a
// test push an SBOM in one end and observe a Faultline/Finding/Publication come out the
// other. It is a developer convenience, NOT a deployment model — production runs per-context
// binaries. The bus makes the contexts collaborate exactly as separate processes would.
package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/observability"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	comminbound "github.com/themis-project/themis/internal/communication/adapters/inbound"
	commstore "github.com/themis-project/themis/internal/communication/adapters/store"
	commwiring "github.com/themis-project/themis/internal/communication/adapters/wiring"

	evstore "github.com/themis-project/themis/internal/evidence/adapters/store"
	evsubjectref "github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	evwiring "github.com/themis-project/themis/internal/evidence/adapters/wiring"

	govinbound "github.com/themis-project/themis/internal/governance/adapters/inbound"
	govstore "github.com/themis-project/themis/internal/governance/adapters/store"
	govwiring "github.com/themis-project/themis/internal/governance/adapters/wiring"

	kninbound "github.com/themis-project/themis/internal/knowledge/adapters/inbound"
	knstore "github.com/themis-project/themis/internal/knowledge/adapters/store"
	knwiring "github.com/themis-project/themis/internal/knowledge/adapters/wiring"
)

const (
	pgPort    = 15588
	releaseID = "rel-pipeline"

	// A minimal CycloneDX SBOM with one PyPI component the fake OSV maps to a CVE.
	sbomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,` +
		`"components":[{"type":"library","name":"urllib3","version":"1.26.20","purl":"pkg:pypi/urllib3@1.26.20","bom-ref":"urllib3"}]}`

	// One OSV vuln record for urllib3 → CVE-2024-1000 (mirrors the OSV client's own fixture).
	osvVuln = `{"id":"CVE-2024-1000","modified":"2024-01-02T00:00:00Z",` +
		`"database_specific":{"severity":"HIGH","cvss_score":7.5},` +
		`"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}`
)

// pipeline is the composed runner: pools per context DB + bus, the wired services, and the
// relay/reader drain points the pump advances.
type pipeline struct {
	knPool *pgxpool.Pool

	evidenceURL string

	evRelay    *evstore.Relay
	kn         knwiring.Knowledge
	knReader   *eventbus.Reader
	gov        govwiring.Governance
	govReader  *eventbus.Reader
	comm       commwiring.Communication
	commReader *eventbus.Reader
}

// pump cascades events through the pipeline for n passes: each context's relay publishes its
// outbox to the bus, and the next context's reader drains and applies. A few passes carry an
// event from Evidence all the way to Communication.
func (p *pipeline) pump(t *testing.T, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := p.evRelay.DeliverPending(ctx); err != nil {
			t.Fatalf("evidence relay: %v", err)
		}
		if _, err := p.knReader.Drain(ctx); err != nil {
			t.Fatalf("knowledge reader: %v", err)
		}
		if _, err := p.kn.Relay.DeliverPending(ctx); err != nil {
			t.Fatalf("knowledge relay: %v", err)
		}
		if _, err := p.govReader.Drain(ctx); err != nil {
			t.Fatalf("governance reader: %v", err)
		}
		if _, err := p.gov.Reconcile.Reconcile(ctx); err != nil {
			t.Fatalf("governance reconcile: %v", err)
		}
		if _, err := p.commReader.Drain(ctx); err != nil {
			t.Fatalf("communication reader: %v", err)
		}
		if _, err := p.comm.Reconcile.Reconcile(ctx); err != nil {
			t.Fatalf("communication reconcile: %v", err)
		}
	}
}

func TestPipeline_SBOMToFaultline(t *testing.T) {
	p := newPipeline(t)

	// Push an SBOM in one end.
	id := uploadSBOM(t, p.evidenceURL)
	t.Logf("registered evidence id=%s", id)

	// Drive the bus: EvidenceRegistered → Knowledge correlates (reads the inventory over
	// Evidence's read API, discovers the CVE via the fake OSV) → a Faultline exists.
	p.pump(t, 3)

	var n int
	if err := p.knPool.QueryRow(context.Background(),
		"SELECT count(*) FROM faultlines WHERE cve=$1", "CVE-2024-1000").Scan(&n); err != nil {
		t.Fatalf("query faultlines: %v", err)
	}
	if n != 1 {
		t.Fatalf("faultlines for CVE-2024-1000 = %d, want 1 (SBOM did not flow Evidence→bus→Knowledge)", n)
	}
	t.Log("pipeline OK: SBOM → Evidence → bus → Knowledge correlated a Faultline")
}

// --- runner setup --------------------------------------------------------------------------

func uploadSBOM(t *testing.T, evidenceURL string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"kind": "sbom", "format": "cyclonedx", "subject_release_id": releaseID, "document": sbomDoc,
	})
	resp, err := http.Post(evidenceURL+"/api/v1/evidence", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload status = %d, want 201", resp.StatusCode)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	return out.ID
}

func newPipeline(t *testing.T) *pipeline {
	t.Helper()
	dir, err := os.MkdirTemp("", "pipeline-*")
	if err != nil {
		t.Fatal(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("postgres").
		Version(embeddedpostgres.V16).Port(pgPort).
		DataPath(filepath.Join(dir, "data")).RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"max_connections": "60"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping pipeline e2e: %v\n", err)
		t.Skip("no database")
	}
	t.Cleanup(func() { _ = db.Stop(); _ = os.RemoveAll(dir) })

	ctx := context.Background()
	admin := mustPool(t, dsnFor("postgres"))
	defer admin.Close()
	for _, name := range []string{"evidence", "knowledge", "governance", "communication", "bus"} {
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatalf("create db %s: %v", name, err)
		}
	}

	migrateDB(t, "evidence", "../../internal/evidence/adapters/store/migrations")
	migrateDB(t, "knowledge", "../../internal/knowledge/adapters/store/migrations")
	migrateDB(t, "governance", "../../internal/governance/adapters/store/migrations")
	migrateDB(t, "communication", "../../internal/communication/adapters/store/migrations")
	migrateDB(t, "bus", "../../internal/platform/eventbus/migrations")

	log := observability.Nop()
	busPool := mustPool(t, dsnFor("bus"))
	t.Cleanup(busPool.Close)

	// A fake OSV endpoint so Knowledge's lazy discovery finds a CVE for the SBOM's component.
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": []json.RawMessage{json.RawMessage(osvVuln)}})
	}))
	t.Cleanup(osv.Close)

	// Evidence: producer of EvidenceRegistered. SubjectRef is stubbed (registry-free dev).
	evPool := mustPool(t, dsnFor("evidence"))
	t.Cleanup(evPool.Close)
	evHandler, _ := evwiring.EvidenceAPI(evPool, evsubjectref.NewStub(releaseID))
	evidenceSrv := httptest.NewServer(mount(evHandler))
	t.Cleanup(evidenceSrv.Close)
	evRelay := evstore.NewRelay(evPool, eventbus.NewPublisher(busPool), 100)

	// Knowledge: consumes the Evidence stream and correlates.
	knPool := mustPool(t, dsnFor("knowledge"))
	t.Cleanup(knPool.Close)
	kn := knwiring.Wire(knPool, evidenceSrv.URL, osv.URL, eventbus.NewPublisher(busPool))
	knReader := kninbound.Subscription.NewReader(busPool, log, knstore.NewInboxConsumer(knPool, kn.Consumer))

	// Governance: consumes the Knowledge stream.
	govPool := mustPool(t, dsnFor("governance"))
	t.Cleanup(govPool.Close)
	gov := govwiring.Wire(govPool, eventbus.NewPublisher(busPool), nil)
	governanceSrv := httptest.NewServer(mount(gov.Handler))
	t.Cleanup(governanceSrv.Close)
	govReader := govinbound.Subscription.NewReader(busPool, log, govstore.NewInboxConsumer(govPool, gov.Consumer))

	// Communication: consumes the Governance stream.
	commPool := mustPool(t, dsnFor("communication"))
	t.Cleanup(commPool.Close)
	comm := commwiring.Wire(commPool, governanceSrv.URL,
		delivery.NewLogDeliverer(log), delivery.PassThroughRedactor{}, eventbus.NewPublisher(busPool))
	commReader := comminbound.Subscription.NewReader(busPool, log, commstore.NewInboxConsumer(commPool, comm.Consumer))

	return &pipeline{
		knPool:      knPool,
		evidenceURL: evidenceSrv.URL,
		evRelay:     evRelay,
		kn:          kn,
		knReader:    knReader,
		gov:         gov,
		govReader:   govReader,
		comm:        comm,
		commReader:  commReader,
	}
}

func mount(h http.Handler) http.Handler {
	r := chi.NewRouter()
	r.Mount("/api/v1", h)
	return r
}

func dsnFor(db string) string {
	return fmt.Sprintf("postgres://themis:themis@localhost:%d/%s?sslmode=disable", pgPort, db)
}

func mustPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool %s: %v", dsn, err)
	}
	return pool
}

func migrateDB(t *testing.T, db, path string) {
	t.Helper()
	abs, _ := filepath.Abs(path)
	m, err := migrate.New("file://"+abs, dsnFor(db))
	if err != nil {
		t.Fatalf("migrate.New %s: %v", db, err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migrate %s: %v", db, err)
	}
}
