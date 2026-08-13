//go:build e2e

// Package pipeline holds the in-process composed pipeline runner (EB-08/09, dev/e2e only): it
// wires all four bounded contexts against ONE PostgreSQL server with a database per context
// plus the dedicated `bus` database, drives them through the platform event bus, and lets a
// test push an SBOM in one end and observe a published OpenVEX artifact come out the other —
// black-box, over the read/triage/publish HTTP APIs, never peeking a context's own tables. It
// is a developer convenience, NOT a deployment model; production runs per-context binaries.
// The bus makes the contexts collaborate exactly as separate processes would.
package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/go-chi/chi/v5"
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
	evwiring "github.com/themis-project/themis/internal/evidence/adapters/wiring"

	govinbound "github.com/themis-project/themis/internal/governance/adapters/inbound"
	govstore "github.com/themis-project/themis/internal/governance/adapters/store"
	govwiring "github.com/themis-project/themis/internal/governance/adapters/wiring"
	govdomain "github.com/themis-project/themis/internal/governance/domain"

	kninbound "github.com/themis-project/themis/internal/knowledge/adapters/inbound"
	knstore "github.com/themis-project/themis/internal/knowledge/adapters/store"
	knwiring "github.com/themis-project/themis/internal/knowledge/adapters/wiring"

	registrystore "github.com/themis-project/themis/internal/registry/adapters/store"
	registrywiring "github.com/themis-project/themis/internal/registry/adapters/wiring"
)

const (
	pgPort    = 15588
	targetCVE = "CVE-2024-1000"

	// A minimal CycloneDX SBOM with one PyPI component the fake OSV maps to a CVE.
	sbomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,` +
		`"components":[{"type":"library","name":"urllib3","version":"1.26.20","purl":"pkg:pypi/urllib3@1.26.20","bom-ref":"urllib3"}]}`

	// One OSV vuln record for urllib3 → CVE-2024-1000 (mirrors the OSV client's own fixture).
	osvVuln = `{"id":"CVE-2024-1000","modified":"2024-01-02T00:00:00Z",` +
		`"database_specific":{"severity":"HIGH","cvss_score":7.5},` +
		`"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}`
)

// pipeline is the composed runner: the three public HTTP surfaces plus the relay/reader drain
// points the pump advances.
type pipeline struct {
	registryURL      string
	evidenceURL      string
	governanceURL    string
	communicationURL string

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
	drive := func(name string, f func(context.Context) (int, error)) {
		if _, err := f(ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for i := 0; i < n; i++ {
		drive("evidence relay", p.evRelay.DeliverPending)
		drive("knowledge reader", p.knReader.Drain)
		drive("knowledge relay", p.kn.Relay.DeliverPending)
		drive("governance reader", p.govReader.Drain)
		drive("governance reconcile", p.gov.Reconcile.Reconcile)
		drive("communication reader", p.commReader.Drain)
		drive("communication reconcile", p.comm.Reconcile.Reconcile)
		drive("communication delivery", p.comm.Delivery.DeliverPending)
	}
}

// TestPipeline_SBOMToPublishedVEX is the black-box M5 pipeline proof (EB-09 / D11): an SBOM
// pushed into Evidence flows over the real bus — Evidence → Knowledge (correlate) → Governance
// (open Finding) — a human governs an "affected" Position, a human triggers an OpenVEX
// publication, and the published artifact appears with the expected stance. Every observation
// is over a public HTTP API; no context's tables are read directly.
func TestPipeline_SBOMToPublishedVEX(t *testing.T) {
	p := newPipeline(t)

	// Register the release through the real Registry (Product → Project → Release), exactly as a
	// greenfield deployment does — Evidence validates the SBOM's subject_release_id against these
	// registered ids (a registry-backed SubjectRef), so an unregistered release would be rejected.
	releaseID := registerRelease(t, p.registryURL)
	t.Logf("registered release: %s", releaseID)

	// SBOM in (its subject is the just-registered release).
	uploadSBOM(t, p.evidenceURL, releaseID)

	// Evidence → Knowledge (correlate) → Governance (open Finding).
	p.pump(t, 3)

	// Discover the Finding black-box via Governance's release posture.
	var posture []struct {
		FindingID string `json:"finding_id"`
		CVE       string `json:"cve"`
	}
	getJSON(t, p.governanceURL+"/api/v1/releases/"+releaseID+"/posture", &posture)
	findingID := ""
	for _, e := range posture {
		if e.CVE == targetCVE {
			findingID = e.FindingID
		}
	}
	if findingID == "" {
		t.Fatalf("no Finding for %s in posture (SBOM did not flow Evidence→Knowledge→Governance): %+v", targetCVE, posture)
	}
	t.Logf("finding opened: %s", findingID)

	// Govern the decision: a human raises an "affected" proposal and accepts it → Position v1.
	var raised struct {
		ProposalID string `json:"proposal_id"`
	}
	postJSON(t, p.governanceURL+"/api/v1/findings/"+findingID+"/proposals",
		map[string]any{"stance": "affected", "proposer_kind": "human", "proposer_id": "e2e"}, http.StatusCreated, &raised)
	postJSON(t, p.governanceURL+"/api/v1/findings/"+findingID+"/proposals/"+raised.ProposalID+"/accept",
		map[string]any{"actor_id": "e2e", "actor_kind": "human"}, http.StatusNoContent, nil)

	// Governance Position → Communication publishable.
	p.pump(t, 3)

	// A human triggers the OpenVEX publication (Communication never auto-publishes).
	var created struct {
		PublicationID string `json:"publication_id"`
	}
	postJSON(t, p.communicationURL+"/api/v1/publications",
		map[string]any{"finding_id": findingID, "artifact_type": "vex", "format": "openvex"}, http.StatusCreated, &created)
	p.pump(t, 2)

	// Assert the published OpenVEX artifact black-box via Communication's read API. The list
	// view omits the rendered payload, so fetch the artifact by id to confirm the OpenVEX
	// document actually names the CVE.
	var pubs []struct {
		ID     string `json:"id"`
		Format string `json:"format"`
		Stance string `json:"stance"`
		CVE    string `json:"cve"`
	}
	getJSON(t, p.communicationURL+"/api/v1/publications?release="+releaseID, &pubs)
	for _, pub := range pubs {
		if pub.Format == "openvex" && pub.CVE == targetCVE && pub.Stance == "affected" {
			var full struct {
				Payload string `json:"payload"`
			}
			getJSON(t, p.communicationURL+"/api/v1/publications/"+pub.ID, &full)
			if !strings.Contains(full.Payload, targetCVE) {
				t.Errorf("OpenVEX payload does not name %s: %s", targetCVE, full.Payload)
			}
			t.Log("pipeline OK: SBOM → Evidence → Knowledge → Governance → Communication published OpenVEX (affected)")
			return
		}
	}
	t.Fatalf("no published OpenVEX (affected) for %s: %+v", targetCVE, pubs)
}

// --- HTTP helpers --------------------------------------------------------------------------

func uploadSBOM(t *testing.T, evidenceURL, releaseID string) {
	t.Helper()
	postJSON(t, evidenceURL+"/api/v1/evidence", map[string]any{
		"kind": "sbom", "format": "cyclonedx", "subject_release_id": releaseID, "document": sbomDoc,
	}, http.StatusCreated, nil)
}

// registerRelease drives the real Registry HTTP API to create a Product → Project → Release chain
// and returns the generated release id — the deployment-faithful way to obtain a subject the
// Evidence context will accept (vs a stubbed SubjectRef).
func registerRelease(t *testing.T, registryURL string) string {
	t.Helper()
	var product, project, release struct {
		ID string `json:"id"`
	}
	postJSON(t, registryURL+"/api/v1/products",
		map[string]any{"name": "acme"}, http.StatusCreated, &product)
	postJSON(t, registryURL+"/api/v1/projects",
		map[string]any{"product_id": product.ID, "name": "api"}, http.StatusCreated, &project)
	postJSON(t, registryURL+"/api/v1/releases",
		map[string]any{"project_id": project.ID, "version": "1.0.0"}, http.StatusCreated, &release)
	if release.ID == "" {
		t.Fatal("registry returned an empty release id")
	}
	return release.ID
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

func postJSON(t *testing.T, url string, body any, wantStatus int, out any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s = %d, want %d: %s", url, resp.StatusCode, wantStatus, msg)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s: %v", url, err)
		}
	}
}

// --- runner setup --------------------------------------------------------------------------

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

	// Registry: co-locates its identity tables in the evidence DB (as in production — it cannot
	// self-migrate there, so load the idempotent schema directly). It serves the Product →
	// Project → Release API the test registers against.
	evPool := mustPool(t, dsnFor("evidence"))
	t.Cleanup(evPool.Close)
	loadSQL(t, evPool, "../../internal/registry/adapters/store/migrations/000001_registry.up.sql")
	regHandler, _ := registrywiring.RegistryAPI(evPool)
	registrySrv := httptest.NewServer(mount(regHandler))
	t.Cleanup(registrySrv.Close)

	// Evidence: producer of EvidenceRegistered. SubjectRef is registry-backed — it validates a
	// release id against the registry tables in the shared evidence DB (registry.ReleaseExists).
	evHandler, _ := evwiring.EvidenceAPI(evPool, registrySubjectRef{store: registrystore.New(evPool)})
	evidenceSrv := httptest.NewServer(mount(evHandler))
	t.Cleanup(evidenceSrv.Close)
	evRelay := evstore.NewRelay(evPool, eventbus.NewPublisher(busPool), 100)

	// Knowledge: consumes the Evidence stream and correlates (no HTTP surface needed here).
	knPool := mustPool(t, dsnFor("knowledge"))
	t.Cleanup(knPool.Close)
	kn := knwiring.Wire(knPool, evidenceSrv.URL, osv.URL, eventbus.NewPublisher(busPool), knwiring.NVDConfig{}, knwiring.SignalsConfig{}, knwiring.RedHatConfig{}, knwiring.AlpineConfig{}, knwiring.VexfeedConfig{}, knwiring.RediscoveryConfig{})
	knReader := kninbound.Subscription.NewReader(busPool, log, knstore.NewInboxConsumer(knPool, kn.Consumer))

	// Governance: consumes the Knowledge stream; serves posture + triage.
	govPool := mustPool(t, dsnFor("governance"))
	t.Cleanup(govPool.Close)
	// Wired exactly as cmd/governance does, including the one shipped auto-accept policy
	// (EDR-GOVERNANCE-01 D15) — the pipeline proof should exercise the real composition, not a
	// permissive or empty one. It changes nothing in this scenario: the human governs an
	// `affected` Position, and the rule only ever accepts a system-raised `not_affected` on
	// Observed evidence.
	gov := govwiring.Wire(govPool, eventbus.NewPublisher(busPool), nil, "", "", 0,
		govdomain.DefaultMitigatedWeight, govdomain.DefaultEPSSDriftThreshold,
		govdomain.AutoAcceptObservedNotAffectedPolicy())
	governanceSrv := httptest.NewServer(mount(gov.Handler))
	t.Cleanup(governanceSrv.Close)
	govReader := govinbound.Subscription.NewReader(busPool, log, govstore.NewInboxConsumer(govPool, gov.Consumer))

	// Communication: consumes the Governance stream; serves publish + read (reads Positions
	// back from Governance over its read API).
	commPool := mustPool(t, dsnFor("communication"))
	t.Cleanup(commPool.Close)
	comm := commwiring.Wire(commPool, governanceSrv.URL,
		delivery.NewLogDeliverer(log), delivery.PassThroughRedactor{}, eventbus.NewPublisher(busPool))
	communicationSrv := httptest.NewServer(mount(comm.Handler))
	t.Cleanup(communicationSrv.Close)
	commReader := comminbound.Subscription.NewReader(busPool, log, commstore.NewInboxConsumer(commPool, comm.Consumer))

	return &pipeline{
		registryURL:      registrySrv.URL,
		evidenceURL:      evidenceSrv.URL,
		governanceURL:    governanceSrv.URL,
		communicationURL: communicationSrv.URL,
		evRelay:          evRelay,
		kn:               kn,
		knReader:         knReader,
		gov:              gov,
		govReader:        govReader,
		comm:             comm,
		commReader:       commReader,
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

// loadSQL executes a .sql file against the pool — used to load the registry schema into the
// evidence DB (the registry co-locates there and cannot self-migrate; the schema is idempotent).
func loadSQL(t *testing.T, pool *pgxpool.Pool, path string) {
	t.Helper()
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
}

// registrySubjectRef backs Evidence's SubjectRef with the registry's ReleaseExists read query
// (mirrors cmd/evidence): in-process it reads the registry tables in the shared evidence DB, so
// Evidence accepts exactly the releases the test registered.
type registrySubjectRef struct{ store *registrystore.Store }

func (v registrySubjectRef) ReleaseExists(ctx context.Context, releaseID string) (bool, error) {
	return v.store.ReleaseExists(ctx, releaseID)
}
