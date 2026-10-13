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
	"net/url"
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

	"github.com/themis-project/themis/internal/platform/auth"
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
	registrydomain "github.com/themis-project/themis/internal/registry/domain"
)

const (
	pgPort = 15588
	// The auth-on pipeline gets its OWN embedded-Postgres port. The two runners are sequential,
	// so one port would usually do; a second port means a slow shutdown of the first instance
	// can never make the second test fail for a reason that has nothing to do with auth.
	pgPortAuth = 15589
	targetCVE  = "CVE-2024-1000"

	// A minimal CycloneDX SBOM with one PyPI component the fake OSV maps to a CVE.
	sbomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,` +
		`"components":[{"type":"library","name":"urllib3","version":"1.26.20","purl":"pkg:pypi/urllib3@1.26.20","bom-ref":"urllib3"}]}`

	// One OSV vuln record for urllib3 → CVE-2024-1000 (mirrors the OSV client's own fixture).
	osvVuln = `{"id":"CVE-2024-1000","modified":"2024-01-02T00:00:00Z",` +
		`"database_specific":{"severity":"HIGH","cvss_score":7.5},` +
		`"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}`
)

// options configure one composed runner. The zero value is NOT valid — newPipeline is always
// called with an explicit port, because the auth-on runner needs its own.
type options struct {
	pgPort int
	// auth switches every node's inbound edge ON: a shared `auth` database, per-node keys, and
	// the same RequireAPIKey + RequireWriteScope middleware each cmd/<ctx> mounts. The test's own
	// calls then carry an admin key, and each node's inter-service client carries its own.
	auth bool
}

// pipeline is the composed runner: the public HTTP surfaces plus the relay/reader drain
// points the pump advances.
type pipeline struct {
	registryURL      string
	evidenceURL      string
	governanceURL    string
	communicationURL string

	// apiKey is the credential the TEST itself presents (an operator's admin key). Empty on the
	// auth-off runner, where the nodes mount no middleware.
	apiKey string

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
	newPipeline(t, options{pgPort: pgPort}).sbomToPublishedVEX(t)
}

// sbomToPublishedVEX is the scenario itself, run by the auth-off proof above and — unchanged,
// which is the point — by the auth-ON proof in pipeline_auth_test.go. Sharing the body is what
// makes the second test a statement about credentials and nothing else: if it passes, the same
// SBOM reached the same published OpenVEX with every node's inbound edge authenticated.
// It returns the Finding id so a caller can make further assertions about it.
func (p *pipeline) sbomToPublishedVEX(t *testing.T) string {
	t.Helper()

	// Register the release through the real Registry (Product → Project → Release), exactly as a
	// greenfield deployment does — Evidence validates the SBOM's subject_release_id against these
	// registered ids (a registry-backed SubjectRef), so an unregistered release would be rejected.
	releaseID := p.registerRelease(t)
	t.Logf("registered release: %s", releaseID)

	// SBOM in (its subject is the just-registered release).
	p.uploadSBOM(t, releaseID)

	// Evidence → Knowledge (correlate) → Governance (open Finding).
	p.pump(t, 3)

	// Discover the Finding black-box via Governance's release posture.
	var posture []struct {
		FindingID string `json:"finding_id"`
		CVE       string `json:"cve"`
	}
	p.getJSON(t, p.governanceURL+"/api/v1/releases/"+releaseID+"/posture", &posture)
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
	p.postJSON(t, p.governanceURL+"/api/v1/findings/"+findingID+"/proposals",
		map[string]any{"stance": "affected", "proposer_kind": "human", "proposer_id": "e2e"}, http.StatusCreated, &raised)
	p.postJSON(t, p.governanceURL+"/api/v1/findings/"+findingID+"/proposals/"+raised.ProposalID+"/accept",
		map[string]any{"actor_id": "e2e", "actor_kind": "human"}, http.StatusNoContent, nil)

	// Governance Position → Communication publishable.
	p.pump(t, 3)

	// A human triggers the OpenVEX publication (Communication never auto-publishes).
	var created struct {
		PublicationID string `json:"publication_id"`
	}
	p.postJSON(t, p.communicationURL+"/api/v1/publications",
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
	p.getJSON(t, p.communicationURL+"/api/v1/publications?release="+releaseID, &pubs)
	for _, pub := range pubs {
		if pub.Format == "openvex" && pub.CVE == targetCVE && pub.Stance == "affected" {
			var full struct {
				Payload string `json:"payload"`
			}
			p.getJSON(t, p.communicationURL+"/api/v1/publications/"+pub.ID, &full)
			if !strings.Contains(full.Payload, targetCVE) {
				t.Errorf("OpenVEX payload does not name %s: %s", targetCVE, full.Payload)
			}
			t.Log("pipeline OK: SBOM → Evidence → Knowledge → Governance → Communication published OpenVEX (affected)")
			return findingID
		}
	}
	t.Fatalf("no published OpenVEX (affected) for %s: %+v", targetCVE, pubs)
	return ""
}

// --- HTTP helpers --------------------------------------------------------------------------

func (p *pipeline) uploadSBOM(t *testing.T, releaseID string) {
	t.Helper()
	p.postJSON(t, p.evidenceURL+"/api/v1/evidence", map[string]any{
		"kind": "sbom", "format": "cyclonedx", "subject_release_id": releaseID, "document": sbomDoc,
	}, http.StatusCreated, nil)
}

// registerRelease drives the real Registry HTTP API to create a Product → Project → Release chain
// and returns the generated release id — the deployment-faithful way to obtain a subject the
// Evidence context will accept (vs a stubbed SubjectRef).
func (p *pipeline) registerRelease(t *testing.T) string {
	t.Helper()
	var product, project, release struct {
		ID string `json:"id"`
	}
	p.postJSON(t, p.registryURL+"/api/v1/products",
		map[string]any{"name": "acme"}, http.StatusCreated, &product)
	p.postJSON(t, p.registryURL+"/api/v1/projects",
		map[string]any{"product_id": product.ID, "name": "api"}, http.StatusCreated, &project)
	p.postJSON(t, p.registryURL+"/api/v1/releases",
		map[string]any{"project_id": project.ID, "version": "1.0.0"}, http.StatusCreated, &release)
	if release.ID == "" {
		t.Fatal("registry returned an empty release id")
	}
	return release.ID
}

// do issues one request carrying the TEST's own credential when the runner is authenticated —
// the operator's X-API-Key, exactly as `scripts/gf-upload-sbom.sh` sends it. Empty on the
// auth-off runner, where the nodes mount no middleware.
func (p *pipeline) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	if p.apiKey != "" {
		req.Header.Set("X-API-Key", p.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

func (p *pipeline) getJSON(t *testing.T, url string, out any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp := p.do(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s = %d, want 200: %s", url, resp.StatusCode, msg)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

func (p *pipeline) postJSON(t *testing.T, url string, body any, wantStatus int, out any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp := p.do(t, req)
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

func newPipeline(t *testing.T, opt options) *pipeline {
	t.Helper()
	dir, err := os.MkdirTemp("", "pipeline-*")
	if err != nil {
		t.Fatal(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("postgres").
		Version(embeddedpostgres.V16).Port(uint32(opt.pgPort)).
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
	admin := mustPool(t, dsnFor(opt.pgPort, "postgres"))
	defer admin.Close()
	// The production topology (INSTALLATION.md Part A): one server, a database per context plus
	// the shared `bus` — and, when the inbound edge is on, the shared `auth` identity database.
	databases := []string{"evidence", "knowledge", "governance", "communication", "bus"}
	if opt.auth {
		databases = append(databases, "auth")
	}
	for _, name := range databases {
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatalf("create db %s: %v", name, err)
		}
	}

	migrateDB(t, opt.pgPort, "evidence", "../../internal/evidence/adapters/store/migrations")
	migrateDB(t, opt.pgPort, "knowledge", "../../internal/knowledge/adapters/store/migrations")
	migrateDB(t, opt.pgPort, "governance", "../../internal/governance/adapters/store/migrations")
	migrateDB(t, opt.pgPort, "communication", "../../internal/communication/adapters/store/migrations")
	migrateDB(t, opt.pgPort, "bus", "../../internal/platform/eventbus/migrations")

	// The inbound edge (EDR-SECURITY-01 D1/D2): the `auth` schema, the minted per-node keys, and
	// the authenticator every node mounts. ONE authenticator is shared by the five in-process
	// nodes rather than five pools against one database — this runner's connection budget is
	// finite and the middleware only ever READS the key table, so the behaviour is identical to
	// five nodes each opening THEMIS_AUTH_DATABASE_DSN.
	var authn *auth.Authenticator
	var keys nodeKeys
	if opt.auth {
		authDSN := dsnFor(opt.pgPort, "auth")
		migrateDB(t, opt.pgPort, "auth", "../../internal/platform/auth/migrations")
		keys = mintNodeKeys(t, authDSN)
		a, closeAuth, err := auth.Open(ctx, authDSN)
		if err != nil {
			t.Fatalf("auth open: %v", err)
		}
		t.Cleanup(closeAuth)
		authn = a
	}

	log := observability.Nop()
	busPool := mustPool(t, dsnFor(opt.pgPort, "bus"))
	t.Cleanup(busPool.Close)

	// A fake OSV endpoint so Knowledge's lazy discovery finds a CVE for the SBOM's component.
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": []json.RawMessage{json.RawMessage(osvVuln)}})
	}))
	t.Cleanup(osv.Close)

	// Registry: co-locates its identity tables in the evidence DB (as in production) and
	// migrates them itself, through its OWN bookkeeping table. It serves the Product →
	// Project → Release API the test registers against.
	evPool := mustPool(t, dsnFor(opt.pgPort, "evidence"))
	t.Cleanup(evPool.Close)
	migrateRegistry(t, opt.pgPort)
	regHandler, _ := registrywiring.RegistryAPI(evPool)
	registrySrv := httptest.NewServer(mount(regHandler, authn))
	t.Cleanup(registrySrv.Close)

	// Evidence: producer of EvidenceRegistered. SubjectRef is registry-backed — it validates a
	// release id against the registry tables in the shared evidence DB (registry.ReleaseExists).
	evHandler, _, evIntake := evwiring.EvidenceAPI(evwiring.Config{
		Pool:     evPool,
		Registry: registrySubjectRef{store: registrystore.New(evPool)},
	})
	t.Cleanup(evIntake.Close)
	evidenceSrv := httptest.NewServer(mount(evHandler, authn))
	t.Cleanup(evidenceSrv.Close)
	evRelay := evstore.NewRelay(evPool, eventbus.NewPublisher(busPool), 100)

	// Knowledge: consumes the Evidence stream and correlates, reading each release's inventory
	// back from Evidence over the read API — the seam that carries keys.knowledge. Its own read
	// API is served too, because Governance reads the assessment projection from it.
	knPool := mustPool(t, dsnFor(opt.pgPort, "knowledge"))
	t.Cleanup(knPool.Close)
	kn := knwiring.Wire(knPool, evidenceSrv.URL, osv.URL, keys.knowledge, eventbus.NewPublisher(busPool), knwiring.NVDConfig{}, knwiring.SignalsConfig{}, knwiring.RedHatConfig{}, knwiring.AlpineConfig{}, knwiring.RockyConfig{}, knwiring.VexfeedConfig{}, knwiring.RediscoveryConfig{}, knwiring.VerdictConfig{})
	knReader := kninbound.Subscription.NewReader(busPool, log, knstore.NewInboxConsumer(knPool, kn.Consumer))
	knowledgeSrv := httptest.NewServer(mount(kn.Handler, authn))
	t.Cleanup(knowledgeSrv.Close)

	// Governance: consumes the Knowledge stream; serves posture + triage.
	govPool := mustPool(t, dsnFor(opt.pgPort, "governance"))
	t.Cleanup(govPool.Close)
	// Wired exactly as cmd/governance does, including the one shipped auto-accept policy
	// (EDR-GOVERNANCE-01 D15) — the pipeline proof should exercise the real composition, not a
	// permissive or empty one. It changes nothing in this scenario: the human governs an
	// `affected` Position, and the rule only ever accepts a system-raised `not_affected` on
	// Observed evidence.
	//
	// All three read seams are wired (Registry for the blast multiplier + the product-scope hop,
	// Knowledge for the assessment projection, Evidence for the compare read), each carrying
	// keys.governance. The posture read in the scenario therefore performs a real authenticated
	// Governance → Registry read on the auth-on runner.
	gov := govwiring.Wire(govPool, eventbus.NewPublisher(busPool), nil,
		registrySrv.URL, knowledgeSrv.URL, evidenceSrv.URL, keys.governance, 0,
		govdomain.DefaultMitigatedWeight, govdomain.DefaultEPSSDriftThreshold, log,
		govdomain.AutoAcceptObservedNotAffectedPolicy())
	governanceSrv := httptest.NewServer(mount(gov.Handler, authn))
	t.Cleanup(governanceSrv.Close)
	govReader := govinbound.Subscription.NewReader(busPool, log, govstore.NewInboxConsumer(govPool, gov.Consumer))

	// Communication: consumes the Governance stream; serves publish + read (reads Positions
	// back from Governance over its read API, and the name chain from Registry).
	commPool := mustPool(t, dsnFor(opt.pgPort, "communication"))
	t.Cleanup(commPool.Close)
	comm := commwiring.Wire(commPool, governanceSrv.URL, registrySrv.URL, keys.communication,
		delivery.NewLogDeliverer(log), delivery.PassThroughRedactor{}, eventbus.NewPublisher(busPool))
	communicationSrv := httptest.NewServer(mount(comm.Handler, authn))
	t.Cleanup(communicationSrv.Close)
	commReader := comminbound.Subscription.NewReader(busPool, log, commstore.NewInboxConsumer(commPool, comm.Consumer))

	return &pipeline{
		registryURL:      registrySrv.URL,
		evidenceURL:      evidenceSrv.URL,
		governanceURL:    governanceSrv.URL,
		communicationURL: communicationSrv.URL,
		apiKey:           keys.operator,
		evRelay:          evRelay,
		kn:               kn,
		knReader:         knReader,
		gov:              gov,
		govReader:        govReader,
		comm:             comm,
		commReader:       commReader,
	}
}

// mount serves one context's API under /api/v1, behind the inbound edge when an authenticator
// is supplied — RequireAPIKey then the method-based RequireWriteScope, the same two middlewares
// every cmd/<ctx>'s authedMount applies. A nil authenticator is the auth-off estate: mounted
// open, exactly as a node with no THEMIS_AUTH_DATABASE_DSN runs.
func mount(h http.Handler, authn *auth.Authenticator) http.Handler {
	r := chi.NewRouter()
	if authn == nil {
		r.Mount("/api/v1", h)
		return r
	}
	r.Group(func(g chi.Router) {
		g.Use(authn.RequireAPIKey)
		g.Use(auth.RequireWriteScope)
		g.Mount("/api/v1", h)
	})
	return r
}

func dsnFor(port int, db string) string {
	return fmt.Sprintf("postgres://themis:themis@localhost:%d/%s?sslmode=disable", port, db)
}

func mustPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool %s: %v", dsn, err)
	}
	return pool
}

func migrateDB(t *testing.T, port int, db, path string) {
	t.Helper()
	abs, _ := filepath.Abs(path)
	m, err := migrate.New("file://"+abs, dsnFor(port, db))
	if err != nil {
		t.Fatalf("migrate.New %s: %v", db, err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migrate %s: %v", db, err)
	}
}

// migrateRegistry applies Registry's migrations into the evidence database through Registry's
// OWN golang-migrate bookkeeping table, exactly as cmd/registry does: both binaries migrate the
// same database, and sharing the default `schema_migrations` makes whichever runs second read
// the other's version and skip its own CREATE TABLEs.
//
// It replaces a hand-loaded `000001_registry.up.sql`, which froze this harness's registry schema
// at the day that line was written — migration 000003's unique indexes were missing, so the
// find-or-create creates (EDR-INTAKE-01 B4) failed with "no unique or exclusion constraint
// matching the ON CONFLICT specification". The migrations DIRECTORY is the source of truth here;
// a file literal is right once and silently wrong afterwards.
func migrateRegistry(t *testing.T, port int) {
	t.Helper()
	abs, _ := filepath.Abs("../../internal/registry/adapters/store/migrations")
	// The migrations-table parameter MUST ride a separate DSN from any pool's: pgx forwards an
	// unknown parameter to Postgres as a startup option and every runtime connection would fail
	// with `unrecognized configuration parameter`.
	u, err := url.Parse(dsnFor(port, "evidence"))
	if err != nil {
		t.Fatalf("parse evidence dsn: %v", err)
	}
	q := u.Query()
	q.Set("x-migrations-table", "registry_schema_migrations")
	u.RawQuery = q.Encode()

	m, err := migrate.New("file://"+abs, u.String())
	if err != nil {
		t.Fatalf("migrate.New registry: %v", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("migrate registry: %v", err)
	}
}

// registrySubjectRef backs Evidence's SubjectRef and intake's read-only release resolution with
// the registry's own read queries (mirrors cmd/evidence): in-process it reads the registry tables
// in the shared evidence DB, so Evidence accepts exactly the releases the test registered.
type registrySubjectRef struct{ store *registrystore.Store }

func (v registrySubjectRef) ReleaseExists(ctx context.Context, releaseID string) (bool, error) {
	return v.store.ReleaseExists(ctx, releaseID)
}

func (v registrySubjectRef) ProductIDByName(ctx context.Context, name string) (string, error) {
	products, err := v.store.ListProducts(ctx, name)
	if err != nil || len(products) != 1 {
		return "", err
	}
	return string(products[0].ID()), nil
}

func (v registrySubjectRef) ProjectIDByName(ctx context.Context, productID, name string) (string, error) {
	projects, err := v.store.ListProjects(ctx, registrydomain.ProductID(productID), name)
	if err != nil || len(projects) != 1 {
		return "", err
	}
	return string(projects[0].ID()), nil
}

func (v registrySubjectRef) ReleaseIDByVersion(ctx context.Context, projectID, version string) (string, error) {
	releases, err := v.store.ListReleases(ctx, registrydomain.ProjectID(projectID))
	if err != nil {
		return "", err
	}
	for _, r := range releases {
		if r.Version() == version {
			return string(r.ID()), nil
		}
	}
	return "", nil
}

// ProductOfRelease is the upward hop both Evidence doors authorize a product-scoped key
// against (EDR-INTAKE-01 B7), delegated to the registry's own query exactly as
// cmd/evidence does. This pipeline runs with auth disabled, so nothing asks it here —
// it is wired because the seam is one interface and a hole in it would only show up on
// a node where auth is ON.
func (v registrySubjectRef) ProductOfRelease(ctx context.Context, releaseID string) (string, error) {
	return v.store.ProductOfRelease(ctx, releaseID)
}
