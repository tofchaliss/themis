//go:build e2e

// Bot intake, end to end on a real auth-enabled node (phase3-bot-intake Group 4,
// tasks 4.2-4.4; EDR-INTAKE-01's 2026-10-12 amendment, B2-B7).
//
// What these tests add over the package's existing Evidence suite is the half the
// amendment lives in and a stubbed seam cannot show:
//
//   - REAL Registry wiring, so `create_release=true` reaches Registry's own
//     `ON CONFLICT` find-or-create rather than a fixture that answers whatever the
//     test author believed;
//   - the REAL inbound-edge auth middleware with REAL minted keys, so the `403`s B3
//     requires to be indistinguishable are compared as BYTES off the wire;
//   - two simultaneous requests against one Postgres, which is the defect the
//     uniqueness constraints exist for and the one a single-threaded test cannot see.
//
// Each test gets its OWN database on the suite's embedded Postgres (created here,
// migrated here), because one of them has to DROP Registry's uniqueness constraints
// to reach the ambiguous-name answer at all, and that must not be visible to the
// others.
//
// THREE SCHEMAS, THREE BOOKKEEPING TABLES. Evidence's, Registry's (co-located as in
// production, EDR-INTAKE-01 D1) and — unlike production, where it is its own database
// — the shared `auth` table all live in that one database. Exactly one of the three
// may use golang-migrate's default `schema_migrations`, because two sharing it is the
// defect the Registry bookkeeping table exists to prevent: whichever ran second would
// read the first one's version and skip its own CREATEs. Evidence keeps the default,
// which is what `cmd/evidence` uses, so the test migrates it exactly as production
// does; Registry takes `registry_schema_migrations` (again production's name) and auth
// `auth_schema_migrations`. That is asserted rather than assumed — [botMigrate] checks
// the applied version against the HIGHEST migration on disk, so a skipped CREATE shows
// up as a version mismatch at setup instead of as a confusing failure later. Auth is a
// read-only `SELECT … FROM api_keys` for the middleware, so sharing the database
// changes no behaviour it enforces — it keeps the node to ONE pool, which is what
// keeps the suite inside the embedded server's connection limit.
//
// SHARED WITH THE EXISTING SUITE. `requireDB` and `testPool` are defined in
// evidence_e2e_test.go, whose `TestMain` starts the one embedded Postgres (or an
// external DB via EVIDENCE_E2E_DSN) for the whole package and records a skip reason
// when it cannot. Nothing here starts a server of its own; the databases below are
// created on that instance.
//
// Run:   make e2e-evidence  (`go test -tags=e2e -count=1 -v ./tests/e2e/...`)
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	// golang-migrate resolves a source and a database by NAME at runtime, from
	// registries its driver packages fill in `init()`. Repeated here, beside the
	// `migrate.New` calls that depend on them, so this file stands on its own: the
	// sibling harness file imports the same two, and whichever of them is dropped
	// first would otherwise turn `botMigrate` into `no source: file` at run time with
	// nothing in THIS file to point at. A package's `init()` runs once per binary
	// however many files import it, so the repetition cannot double-register (which
	// would panic — both Register functions refuse a duplicate name).
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	evhttp "github.com/themis-project/themis/internal/evidence/adapters/http"
	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	evwiring "github.com/themis-project/themis/internal/evidence/adapters/wiring"
	"github.com/themis-project/themis/internal/platform/auth"
	registrystore "github.com/themis-project/themis/internal/registry/adapters/store"
	registrywiring "github.com/themis-project/themis/internal/registry/adapters/wiring"
	registryapp "github.com/themis-project/themis/internal/registry/app"
)

const (
	// botInlineBudget is generous on purpose. The door answers `202` and continues on
	// the overflow worker once the inline budget expires (D9), which is correct
	// behaviour and useless here: every assertion below is about the SYNCHRONOUS
	// answer — the status code, `created`, the echoed `build_id` — so a budget short
	// enough to be hit by a slow embedded Postgres would turn a real failure into an
	// `accepted` receipt and a confusing diff.
	botInlineBudget = 60 * time.Second

	// botTestTimeout bounds the concurrency test's own requests (4.4), so a wedged
	// node fails the test instead of hanging the suite.
	botTestTimeout = 2 * time.Minute

	// botObservedAt is the scan report's asserted observation time (D3). A literal,
	// not `now()`: a report stamped at upload time is indistinguishable from a real
	// re-scan, which is the thing `observed_at` exists to keep apart.
	botObservedAt = "2026-09-01T06:00:00Z"
)

// The SBOMs these tests submit. They are DISTINCT documents by design: Evidence is
// content-addressed, so the same bytes pointed at a different release are refused
// with a loud `409` (EDR-EVIDENCE-01 D3 note) — a test that files twice needs two
// documents, not two releases for one document.
const (
	botSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": { "component": { "type": "application", "name": "bot-app", "version": "1.0.0" } },
  "components": [
    { "bom-ref": "ref-openssl", "type": "library", "name": "openssl", "version": "3.0.11", "purl": "pkg:deb/debian/openssl@3.0.11" }
  ]
}`

	botSBOMSecond = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": { "component": { "type": "application", "name": "bot-app", "version": "2.0.0" } },
  "components": [
    { "bom-ref": "ref-zlib", "type": "library", "name": "zlib", "version": "1.3", "purl": "pkg:deb/debian/zlib@1.3" }
  ]
}`

	botSBOMThird = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": { "component": { "type": "application", "name": "bot-app", "version": "3.0.0" } },
  "components": [
    { "bom-ref": "ref-curl", "type": "library", "name": "curl", "version": "8.9.1", "purl": "pkg:deb/debian/curl@8.9.1" }
  ]
}`
)

// botScanReport is one curated scanner report — the second of B1's two requests. It
// is already-curated, so intake identifies it and files the submitted bytes
// unchanged.
const botScanReport = `{"findings":[{"cve":"CVE-2023-45853","observed_at":"` + botObservedAt +
	`","scanner":"trivy","severity":"high","component":{"purl":"pkg:deb/debian/zlib@1.3","name":"zlib","version":"1.3","ecosystem":"deb"}}]}`

// TestBotIntakeCreateReleaseThenScanReport is task 4.2: the bot road, end to end, in
// the two requests B1 describes — the SBOM request creates the version, the report
// request finds it — followed by the retry whose `build_id` differs.
//
// The third step is the one worth the harness. A byte-identical re-submission dedups
// (D8), and the FILED row keeps the first upload's `build_id` because immutability
// requires it (CON-0007), while the RECEIPT carries what THIS attempt submitted (B5).
// The two values differ by design, and only a test that reads both can tell that
// asymmetry from a bug.
func TestBotIntakeCreateReleaseThenScanReport(t *testing.T) {
	node := startBotNode(t, "bot_intake_create")

	const (
		product = "OAMP-bot"
		project = "oamp-core"
		version = "R2026.001"
	)
	productID := node.registerProduct(t, product)
	projectID := node.registerProject(t, productID, project)
	botKey := node.mintKey(t, "ci-bot", auth.ProductScopePrefix+productID)

	// Nothing is registered under the project yet: the version the first request
	// names is what `create_release=true` is for.
	if versions := node.releaseVersions(t, projectID); len(versions) != 0 {
		t.Fatalf("project starts with releases %v, want none", versions)
	}

	// 1. The SBOM request, with the triple and create_release=true.
	status, raw := node.intake(t, botKey,
		botWith(botTriple(product, project, version), "create_release", "true", "build_id", "build-1"),
		"application/json", botSBOM)
	if status != http.StatusCreated {
		t.Fatalf("create_release SBOM status = %d, want 201: %s", status, raw)
	}
	first := botDecodeReceipt(t, raw)
	if first.Status != "filed" {
		t.Fatalf("receipt status = %q, want filed: %s", first.Status, raw)
	}
	if first.BuildID != "build-1" {
		t.Errorf("receipt build_id = %q, want %q", first.BuildID, "build-1")
	}
	if first.Created == nil || !*first.Created {
		t.Errorf("receipt created = %v, want true", first.Created)
	}
	if first.ReleaseID == "" || first.EvidenceID == "" {
		t.Fatalf("receipt names no release/evidence: %s", raw)
	}

	// The version now exists in Registry — read back over Registry's own API, which
	// is the only authority on what "the Release exists" means.
	if got := node.releaseVersions(t, projectID); len(got) != 1 || got[0] != version {
		t.Fatalf("registry releases = %v, want exactly [%s]", got, version)
	}
	if id := node.releaseIDOf(t, projectID, version); id != first.ReleaseID {
		t.Errorf("registry release id = %s, receipt said %s", id, first.ReleaseID)
	}

	// 2. The report request: the SAME triple, no create_release, a scan report. It
	// must land on the release request 1 created — that is the whole of B1.
	status, raw = node.intake(t, botKey, botTriple(product, project, version),
		"application/json", botScanReport)
	if status != http.StatusCreated {
		t.Fatalf("scan-report status = %d, want 201: %s", status, raw)
	}
	report := botDecodeReceipt(t, raw)
	if report.ReleaseID != first.ReleaseID {
		t.Errorf("scan report filed against release %s, want %s", report.ReleaseID, first.ReleaseID)
	}
	if report.DetectedKind != "vuln-report" || report.DetectedFormat != "curated" {
		t.Errorf("detected %s/%s, want vuln-report/curated", report.DetectedKind, report.DetectedFormat)
	}
	if report.EvidenceID == first.EvidenceID {
		t.Error("the scan report reused the SBOM's evidence id — two documents were filed as one")
	}

	// 3. Request 1 replayed byte-identically, with a DIFFERENT build_id.
	status, raw = node.intake(t, botKey,
		botWith(botTriple(product, project, version), "create_release", "true", "build_id", "build-2"),
		"application/json", botSBOM)
	if status != http.StatusOK {
		t.Fatalf("replay status = %d, want 200 (the document is already held): %s", status, raw)
	}
	replay := botDecodeReceipt(t, raw)
	if replay.Created == nil || *replay.Created {
		t.Errorf("replay created = %v, want an explicit false (D12)", replay.Created)
	}
	if replay.EvidenceID != first.EvidenceID {
		t.Errorf("replay evidence id = %s, want the deduped %s", replay.EvidenceID, first.EvidenceID)
	}
	if replay.BuildID != "build-2" {
		t.Errorf("replay receipt build_id = %q, want the value THIS attempt submitted (%q)", replay.BuildID, "build-2")
	}
	if filed := node.evidenceBuildID(t, first.EvidenceID); filed != "build-1" {
		t.Errorf("filed evidence provenance_build_id = %q, want the FIRST upload's %q", filed, "build-1")
	}

	// One version named three times is one Release.
	if got := node.releaseVersions(t, projectID); len(got) != 1 || got[0] != version {
		t.Fatalf("registry releases after three requests = %v, want exactly [%s]", got, version)
	}
}

// TestBotIntakeAuthNonLeakMatrix is task 4.3: B3's non-disclosure, asserted on the
// bytes, on all three write doors a product-scoped key can reach.
//
// The property is not "these requests are refused" — that is easy and uninteresting.
// It is that a `product:<P>` key cannot TELL THE OUTCOMES APART: someone else's
// product, no such product, an ambiguous name, someone else's release id and a
// release id that does not exist must all be the same response, or intake is a
// product-name and release-id oracle for any holder of any product key. So the
// refusals are compared byte for byte, and the admin arm is run on the same requests
// to show that the honest answers exist and are simply not shown to a confined key.
func TestBotIntakeAuthNonLeakMatrix(t *testing.T) {
	node := startBotNode(t, "bot_intake_nonleak")

	pProductID := node.registerProduct(t, "PROD-P")
	pProjectID := node.registerProject(t, pProductID, "p-core")
	pReleaseID := node.registerRelease(t, pProjectID, "P-1")
	qProductID := node.registerProduct(t, "PROD-Q")
	qProjectID := node.registerProject(t, qProductID, "q-core")
	qReleaseID := node.registerRelease(t, qProjectID, "Q-1")
	pKey := node.mintKey(t, "p-bot", auth.ProductScopePrefix+pProductID)

	// The ambiguous name is seeded AFTER the estate, and by removing Registry's
	// uniqueness, because with migration 000003 applied it is unreachable — which is
	// the point of 000003. It is still reachable on an estate that has not taken that
	// migration yet, so the refusal has to hold there too. The removal also disables
	// Registry's `ON CONFLICT` upserts (an index is what they infer against), so
	// NOTHING may be registered past this line.
	node.dropRegistryUniqueness(t)
	node.seedDuplicateProduct(t, "TWINS")

	// --- the name road, confined key: three outcomes, one answer ---------------
	nameCases := []struct {
		what  string
		query url.Values
	}{
		{"another product's name", botTriple("PROD-Q", "q-core", "Q-2")},
		{"a name that is registered nowhere", botTriple("PROD-NOPE", "p-core", "P-2")},
		{"a name that is registered twice", botTriple("TWINS", "p-core", "P-2")},
	}
	var nameRefusal []byte
	for _, tc := range nameCases {
		status, raw := node.intake(t, pKey, botWith(tc.query, "create_release", "true"),
			"application/json", botSBOM)
		if status != http.StatusForbidden {
			t.Fatalf("name road, %s: status = %d, want 403: %s", tc.what, status, raw)
		}
		if ref := botDecodeRefusal(t, raw); ref.Reason != "unauthorized" {
			t.Errorf("name road, %s: reason = %q, want unauthorized", tc.what, ref.Reason)
		}
		// The refusal carries NOTHING that varies per request, and that is
		// load-bearing rather than tidy: byte-equality is only achievable because the
		// body is a constant. A fresh `intake_id` would break it on exactly the field
		// a caller can replay against, and so would a correlation or trace id. The
		// attempt is still RECORDED — it is the WIRE that says nothing (B3).
		//
		// The field set is asserted rather than just the absence of `intake_id`, so a
		// per-request field added LATER is named by this test as the cause instead of
		// surfacing as an unexplained byte difference. If that ever fires it is a
		// contract break in B3, not a flaky test: the fix is to keep the field off
		// this body, not to relax the comparison.
		if got := botFieldNames(t, raw); !botSameFields(got, botUnauthorizedFields) {
			t.Errorf("name road, %s: refusal fields = %v, want exactly %v — a per-request field here would make the three refusals distinguishable: %s",
				tc.what, got, botUnauthorizedFields, raw)
		}
		if nameRefusal == nil {
			nameRefusal = raw
			continue
		}
		if !bytes.Equal(nameRefusal, raw) {
			t.Errorf("name road, %s: the refusal differs from the first one, so a product key can tell the cases apart\n first: %s\n  this: %s",
				tc.what, nameRefusal, raw)
		}
	}
	// A refusal creates nothing — the whole reason the version find-or-create sits
	// after every border check (B2). Q's project must still hold only Q-1.
	if got := node.releaseVersions(t, qProjectID); len(got) != 1 || got[0] != "Q-1" {
		t.Errorf("another product's releases after three refused create_release requests = %v, want [Q-1]", got)
	}

	// The negative control, and it matters: the `403`s are not a blanket answer. A
	// project that does not exist under the key's OWN product is told so, by name.
	status, raw := node.intake(t, pKey,
		botWith(botTriple("PROD-P", "no-such-project", "P-2"), "create_release", "true"),
		"application/json", botSBOM)
	if status != http.StatusNotFound {
		t.Fatalf("own product, missing project: status = %d, want 404: %s", status, raw)
	}
	ownMiss := botDecodeRefusal(t, raw)
	if ownMiss.Reason != "unknown_release" || !strings.Contains(ownMiss.Detail, "no-such-project") {
		t.Errorf("own product, missing project: reason=%q detail=%q, want unknown_release naming the project",
			ownMiss.Reason, ownMiss.Detail)
	}

	// --- the name road, admin: the answers a confined key is not shown ---------
	adminNameCases := []struct {
		what       string
		query      url.Values
		wantStatus int
		wantReason string
		wantInText string
	}{
		{"no such product", botTriple("PROD-NOPE", "p-core", "P-2"), http.StatusNotFound, "unknown_release", "PROD-NOPE"},
		{"no such project", botTriple("PROD-P", "no-such-project", "P-2"), http.StatusNotFound, "unknown_release", "no-such-project"},
		{"no such version", botTriple("PROD-P", "p-core", "P-404"), http.StatusNotFound, "unknown_release", "P-404"},
		{"a twice-registered name", botTriple("TWINS", "p-core", "P-2"), http.StatusUnprocessableEntity, "ambiguous_name", "TWINS"},
	}
	for _, tc := range adminNameCases {
		// No create_release here: what is under test is the resolution answer, and
		// `create_release` would turn the missing-version case into a creation.
		status, raw := node.intake(t, node.admin, tc.query, "application/json", botSBOM)
		if status != tc.wantStatus {
			t.Fatalf("admin, %s: status = %d, want %d: %s", tc.what, status, tc.wantStatus, raw)
		}
		ref := botDecodeRefusal(t, raw)
		if ref.Reason != tc.wantReason {
			t.Errorf("admin, %s: reason = %q, want %q", tc.what, ref.Reason, tc.wantReason)
		}
		if !strings.Contains(ref.Detail, tc.wantInText) {
			t.Errorf("admin, %s: detail = %q, want it to name %q", tc.what, ref.Detail, tc.wantInText)
		}
	}
	// And the case the confined key saw as `403` is, for admin, no refusal at all:
	// the triple resolves and the document files. Same request, different key.
	status, raw = node.intake(t, node.admin, botTriple("PROD-Q", "q-core", "Q-1"),
		"application/json", botSBOM)
	if status != http.StatusCreated {
		t.Fatalf("admin on another product's release: status = %d, want 201: %s", status, raw)
	}

	// --- the release_id road, confined key ------------------------------------
	idCases := []struct {
		what      string
		releaseID string
	}{
		{"another product's release id", qReleaseID},
		{"a release id that does not exist", uuid.NewString()},
	}
	var idRefusal []byte
	for _, tc := range idCases {
		status, raw := node.intake(t, pKey, url.Values{"release_id": {tc.releaseID}},
			"application/json", botSBOMSecond)
		if status != http.StatusForbidden {
			t.Fatalf("release_id road, %s: status = %d, want 403: %s", tc.what, status, raw)
		}
		if ref := botDecodeRefusal(t, raw); ref.Reason != "unauthorized" {
			t.Errorf("release_id road, %s: reason = %q, want unauthorized", tc.what, ref.Reason)
		}
		if idRefusal == nil {
			idRefusal = raw
			continue
		}
		if !bytes.Equal(idRefusal, raw) {
			t.Errorf("release_id road, %s: the refusal differs from the first one\n first: %s\n  this: %s",
				tc.what, idRefusal, raw)
		}
	}
	// Its own release id files, so the refusals above are about authorization and not
	// about the door being shut.
	status, raw = node.intake(t, pKey, url.Values{"release_id": {pReleaseID}},
		"application/json", botSBOMSecond)
	if status != http.StatusCreated {
		t.Fatalf("release_id road, own release: status = %d, want 201: %s", status, raw)
	}
	if rec := botDecodeReceipt(t, raw); rec.ReleaseID != pReleaseID {
		t.Errorf("release_id road, own release: filed against %s, want %s", rec.ReleaseID, pReleaseID)
	}
	// Admin keeps this road's unchanged answer for an id that is not registered.
	status, raw = node.intake(t, node.admin, url.Values{"release_id": {uuid.NewString()}},
		"application/json", botSBOMThird)
	if status != http.StatusNotFound {
		t.Fatalf("release_id road, admin + unknown id: status = %d, want 404: %s", status, raw)
	}
	if ref := botDecodeRefusal(t, raw); ref.Reason != "unknown_release" {
		t.Errorf("release_id road, admin + unknown id: reason = %q, want unknown_release", ref.Reason)
	}

	// --- POST /evidence: the old door is not a way around the new one (B7) ----
	var oldRefusal []byte
	for _, tc := range idCases {
		status, raw := node.registerEvidence(t, pKey, tc.releaseID, botSBOMThird)
		if status != http.StatusForbidden {
			t.Fatalf("POST /evidence, %s: status = %d, want 403: %s", tc.what, status, raw)
		}
		if title := botDecodeProblemTitle(t, raw); title != "unauthorized" {
			t.Errorf("POST /evidence, %s: title = %q, want %q", tc.what, title, "unauthorized")
		}
		if oldRefusal == nil {
			oldRefusal = raw
			continue
		}
		if !bytes.Equal(oldRefusal, raw) {
			t.Errorf("POST /evidence, %s: the refusal differs from the first one\n first: %s\n  this: %s",
				tc.what, oldRefusal, raw)
		}
	}
	status, raw = node.registerEvidence(t, pKey, pReleaseID, botSBOMThird)
	if status != http.StatusCreated {
		t.Fatalf("POST /evidence, own release: status = %d, want 201: %s", status, raw)
	}
	// Admin on this door keeps ITS existing answer, which is not the intake door's:
	// `POST /evidence` has always met an unregistered subject with
	// `422 unknown subject release` (EDR-EVIDENCE-01 D5), and B7 moved nothing for an
	// unconfined caller. Asserting the intake door's `404` here would be asserting a
	// change this change did not make.
	status, raw = node.registerEvidence(t, node.admin, uuid.NewString(), botSBOMThird)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("POST /evidence, admin + unknown id: status = %d, want this door's existing 422: %s", status, raw)
	}
	if title := botDecodeProblemTitle(t, raw); title != "unknown subject release" {
		t.Errorf("POST /evidence, admin + unknown id: title = %q, want %q", title, "unknown subject release")
	}
}

// TestBotIntakeCreateReleaseConcurrent is task 4.4: two bots building the same
// version at the same moment.
//
// This is the defect Registry's uniqueness constraints exist for. Both requests
// resolve the version as absent, both reach the find-or-create, and the database —
// not the application — decides there is one Release. A single-threaded test cannot
// see it: it would file the first, find the second, and never exercise the conflict.
func TestBotIntakeCreateReleaseConcurrent(t *testing.T) {
	node := startBotNode(t, "bot_intake_concurrent")

	const (
		product = "PROD-CONC"
		project = "conc-core"
		version = "R2026.concurrent"
	)
	productID := node.registerProduct(t, product)
	projectID := node.registerProject(t, productID, project)
	botKey := node.mintKey(t, "conc-bot", auth.ProductScopePrefix+productID)

	ctx, cancel := context.WithTimeout(context.Background(), botTestTimeout)
	defer cancel()

	target := node.evidence.URL + "/api/v1/intake?" +
		botWith(botTriple(product, project, version), "create_release", "true").Encode()

	type outcome struct {
		status  int
		receipt botReceipt
		raw     []byte
		err     error
	}
	const racers = 2
	results := make([]outcome, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release both goroutines together
			status, raw, err := botDo(ctx, http.MethodPost, target, botKey, "application/json", botSBOM)
			out := outcome{status: status, raw: raw, err: err}
			if err == nil {
				_ = json.Unmarshal(raw, &out.receipt)
			}
			results[i] = out
		}(i)
	}
	close(start)
	wg.Wait()

	creations, releaseID := 0, ""
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("racer %d: %v", i, r.err)
		}
		if r.status != http.StatusCreated && r.status != http.StatusOK {
			t.Fatalf("racer %d: status = %d, want 201 or 200: %s", i, r.status, r.raw)
		}
		if r.receipt.Status != "filed" {
			t.Fatalf("racer %d: receipt status = %q, want filed: %s", i, r.receipt.Status, r.raw)
		}
		if r.receipt.ReleaseID == "" {
			t.Fatalf("racer %d: receipt names no release: %s", i, r.raw)
		}
		switch {
		case releaseID == "":
			releaseID = r.receipt.ReleaseID
		case r.receipt.ReleaseID != releaseID:
			t.Errorf("the racers were given different releases: %s vs %s", r.receipt.ReleaseID, releaseID)
		}
		if r.receipt.Created != nil && *r.receipt.Created {
			creations++
		}
	}
	// Both answered successfully; exactly one of them filed the document, which is
	// what makes the other one's `200` honest rather than a silent overwrite.
	//
	// `created` is always PRESENT on a filed receipt — the edge fills in the explicit
	// false when the use case did not create (D12) — so "exactly one true" is a claim
	// about the two answers and not about which fields they happened to carry.
	if creations != 1 {
		t.Errorf("receipts reporting created=true = %d, want exactly 1", creations)
	}
	// And the same fact read STRUCTURALLY, which is what makes the flag assertion
	// above more than a report about itself: one evidence row, one fingerprint. Two
	// rows with one `created=true` between them would be the worse bug, and the flags
	// alone could not see it.
	if rows, fingerprints := node.evidenceRows(t, releaseID); rows != 1 || fingerprints != 1 {
		t.Errorf("evidence rows for %s = %d (%d distinct fingerprints), want 1 and 1",
			releaseID, rows, fingerprints)
	}
	if got := node.releaseVersions(t, projectID); len(got) != 1 || got[0] != version {
		t.Fatalf("registry releases = %v, want exactly [%s] — the version forked", got, version)
	}
}

// --- the node -------------------------------------------------------------

// botNode is one deployment-shaped pair of services over one database: the Evidence
// node (the intake door and `POST /evidence`) and the Registry node (the identity a
// triple resolves against), both behind the real inbound-edge auth middleware.
type botNode struct {
	evidence *httptest.Server
	registry *httptest.Server
	pool     *pgxpool.Pool
	// admin is an `admin`-scoped key: the operator who registers Products and
	// Projects, which intake is structurally incapable of creating (B2).
	admin string
}

// startBotNode creates and migrates a database of its own, wires both services over
// it, and mints the admin key. Everything is torn down with the test.
func startBotNode(t *testing.T, dbName string) *botNode {
	t.Helper()
	requireDB(t)
	ctx := context.Background()

	ident := pgx.Identifier{dbName}.Sanitize()
	if _, err := testPool.Exec(ctx, "DROP DATABASE IF EXISTS "+ident); err != nil {
		t.Fatalf("drop database %s: %v", dbName, err)
	}
	if _, err := testPool.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		t.Fatalf("create database %s: %v", dbName, err)
	}
	dsn := botDSN(t, testPool.Config().ConnString(), dbName)

	// Each schema through its own bookkeeping table (see the file comment).
	botMigrate(t, dsn, filepath.Join("internal", "evidence", "adapters", "store", "migrations"), "")
	botMigrate(t, dsn, filepath.Join("internal", "registry", "adapters", "store", "migrations"), "registry_schema_migrations")
	botMigrate(t, dsn, filepath.Join("internal", "platform", "auth", "migrations"), "auth_schema_migrations")

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	// Small on purpose: the suite's embedded Postgres runs with a low
	// max_connections, and this pool is the node's only one.
	cfg.MaxConns = 5
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool for %s: %v", dbName, err)
	}
	t.Cleanup(pool.Close)

	authn := auth.Authenticator{Keys: auth.NewStore(pool)}

	regHandler, _ := registrywiring.RegistryAPI(pool)
	registrySrv := httptest.NewServer(botMount(authn, regHandler))
	t.Cleanup(registrySrv.Close)

	// The registry seam, read and write, exactly as cmd/evidence assembles it: the
	// read half answers release existence, name resolution and "which product owns
	// this release", and the write half is the one operation B2 permits.
	seam := botRegistrySeam{store: registrystore.New(pool)}
	evHandler, _, intake := evwiring.EvidenceAPI(evwiring.Config{
		Pool:      pool,
		Registry:  seam,
		Provision: subjectref.NewProvisioner(seam),
		Intake:    evhttp.IntakeConfig{InlineBudget: botInlineBudget},
	})
	t.Cleanup(intake.Close)
	evidenceSrv := httptest.NewServer(botMount(authn, evHandler))
	t.Cleanup(evidenceSrv.Close)

	node := &botNode{evidence: evidenceSrv, registry: registrySrv, pool: pool}
	node.admin = node.mintKey(t, "operator", auth.ScopeAdmin)
	return node
}

// botMount is the authenticated mount every node in this file serves: RequireAPIKey
// then the method-based write floor, with `/api/v1` inside the group — the same chain
// cmd/evidence and cmd/registry build when THEMIS_AUTH_DATABASE_DSN is set. Running
// the REAL middleware is the point: these tests assert what a client receives, and a
// hand-rolled stand-in would assert what the test author believed.
func botMount(authn auth.Authenticator, h http.Handler) http.Handler {
	r := chi.NewRouter()
	r.Group(func(g chi.Router) {
		g.Use(authn.RequireAPIKey)
		g.Use(auth.RequireWriteScope)
		g.Mount("/api/v1", h)
	})
	return r
}

// mintKey stores a key with the given scopes and returns the raw token, which is the
// only moment it exists in the clear (EDR-SECURITY-01 D3).
func (n *botNode) mintKey(t *testing.T, name string, scopes ...string) string {
	t.Helper()
	raw, hash, err := auth.GenerateKey()
	if err != nil {
		t.Fatalf("generate key %q: %v", name, err)
	}
	err = auth.NewStore(n.pool).CreateKey(context.Background(), auth.APIKey{
		ID: uuid.NewString(), Name: name, KeyHash: hash, Scopes: scopes,
	})
	if err != nil {
		t.Fatalf("create key %q: %v", name, err)
	}
	return raw
}

// --- Registry, over its own API -------------------------------------------

func (n *botNode) registerProduct(t *testing.T, name string) string {
	t.Helper()
	return n.findOrCreate(t, "/api/v1/products", map[string]any{"name": name})
}

func (n *botNode) registerProject(t *testing.T, productID, name string) string {
	t.Helper()
	return n.findOrCreate(t, "/api/v1/projects", map[string]any{"product_id": productID, "name": name})
}

func (n *botNode) registerRelease(t *testing.T, projectID, version string) string {
	t.Helper()
	return n.findOrCreate(t, "/api/v1/releases", map[string]any{"project_id": projectID, "version": version})
}

func (n *botNode) findOrCreate(t *testing.T, path string, body map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s request: %v", path, err)
	}
	status, resp, err := botDo(context.Background(), http.MethodPost, n.registry.URL+path,
		n.admin, "application/json", string(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want 201 or 200: %s", path, status, resp)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatalf("decode %s response: %v", path, err)
	}
	if out.ID == "" {
		t.Fatalf("POST %s returned an empty id: %s", path, resp)
	}
	return out.ID
}

// releaseVersions lists a project's registered versions over Registry's read API —
// the authority on "how many Releases are there", asked of Registry rather than
// counted in Evidence's own tables.
func (n *botNode) releaseVersions(t *testing.T, projectID string) []string {
	t.Helper()
	out := make([]string, 0, 4)
	for _, r := range n.releases(t, projectID) {
		out = append(out, r.Version)
	}
	return out
}

func (n *botNode) releaseIDOf(t *testing.T, projectID, version string) string {
	t.Helper()
	for _, r := range n.releases(t, projectID) {
		if r.Version == version {
			return r.ID
		}
	}
	t.Fatalf("registry holds no release %q under project %s", version, projectID)
	return ""
}

type botReleaseView struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

func (n *botNode) releases(t *testing.T, projectID string) []botReleaseView {
	t.Helper()
	status, raw, err := botDo(context.Background(), http.MethodGet,
		n.registry.URL+"/api/v1/projects/"+projectID+"/releases", n.admin, "", "")
	if err != nil {
		t.Fatalf("GET releases of %s: %v", projectID, err)
	}
	if status != http.StatusOK {
		t.Fatalf("GET releases of %s status = %d: %s", projectID, status, raw)
	}
	var out []botReleaseView
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode releases of %s: %v", projectID, err)
	}
	return out
}

// registryUniquenessTables are the three tables migration 000003 made unique.
var registryUniquenessTables = []string{"products", "projects", "releases"}

// dropRegistryUniqueness removes whatever enforces Registry's uniqueness, which is
// what makes an ambiguous name reachable at all.
//
// It is SQL rather than a down-migration because only the uniqueness is to go: a
// `migrate down` would take the estate tables with it. And it is INTROSPECTED rather
// than a list of names, which matters for a reason beyond tidiness: this test's whole
// subject is the estate that has NOT taken 000003, so pinning it to that migration's
// three index names would make the test assert the shape of the thing it is supposed
// to be independent of. Renaming an index, or promoting one to a UNIQUE constraint,
// would then fail this test for a reason that has nothing to do with intake.
//
// Primary keys are left alone (`NOT i.indisprimary`): they are unique indexes too,
// they are on `id`, and they have no bearing on whether a NAME is ambiguous. A unique
// index backing a constraint must be dropped through the constraint, which is why both
// forms are handled.
//
// Registry's find-or-create upserts stop working afterwards — `ON CONFLICT` infers
// nothing once the index is gone — so the caller registers the whole estate first.
func (n *botNode) dropRegistryUniqueness(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, u := range n.registryUniqueness(t) {
		var stmt string
		if u.constraint != "" {
			stmt = "ALTER TABLE " + pgx.Identifier{u.table}.Sanitize() +
				" DROP CONSTRAINT IF EXISTS " + pgx.Identifier{u.constraint}.Sanitize()
		} else {
			stmt = "DROP INDEX IF EXISTS " + pgx.Identifier{u.index}.Sanitize()
		}
		if _, err := n.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
		t.Logf("dropped registry uniqueness: %s", u)
	}
	// "I ran three DROPs" is not the same fact as "nothing enforces uniqueness any
	// more", and only the second one makes the ambiguous case reachable. A silent
	// no-op here would otherwise surface as the ambiguity test quietly asserting the
	// wrong thing.
	if left := n.registryUniqueness(t); len(left) != 0 {
		t.Fatalf("registry uniqueness survived the drop: %v", left)
	}
}

// registryUniqueness is every non-primary-key unique index on the three Registry
// tables, with the constraint that owns it when one does.
type registryUniqueIndex struct {
	table      string
	index      string
	constraint string
}

func (u registryUniqueIndex) String() string {
	if u.constraint != "" {
		return u.table + " constraint " + u.constraint
	}
	return u.table + " index " + u.index
}

func (n *botNode) registryUniqueness(t *testing.T) []registryUniqueIndex {
	t.Helper()
	rows, err := n.pool.Query(context.Background(), `
		SELECT tbl.relname, idx.relname, COALESCE(con.conname, '')
		  FROM pg_index i
		  JOIN pg_class idx ON idx.oid = i.indexrelid
		  JOIN pg_class tbl ON tbl.oid = i.indrelid
		  JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
		  LEFT JOIN pg_constraint con
		         ON con.conindid = i.indexrelid AND con.contype IN ('u', 'p')
		 WHERE ns.nspname = current_schema()
		   AND tbl.relname = ANY($1)
		   AND i.indisunique
		   AND NOT i.indisprimary
		 ORDER BY tbl.relname, idx.relname`, registryUniquenessTables)
	if err != nil {
		t.Fatalf("introspect registry uniqueness: %v", err)
	}
	defer rows.Close()
	var out []registryUniqueIndex
	for rows.Next() {
		var u registryUniqueIndex
		if err := rows.Scan(&u.table, &u.index, &u.constraint); err != nil {
			t.Fatalf("scan registry uniqueness: %v", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("introspect registry uniqueness: %v", err)
	}
	return out
}

// seedDuplicateProduct inserts the same Product name twice, straight into the table:
// the pre-000003 estate B3's third indistinguishable outcome describes.
//
// The row count is read back, because the ambiguous case is only ambiguous if TWO
// rows are there — an insert that was silently refused would leave the test asserting
// the "no such product" refusal under the ambiguous case's name, which is the one
// failure mode that would look like a pass.
func (n *botNode) seedDuplicateProduct(t *testing.T, name string) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_, err := n.pool.Exec(ctx,
			`INSERT INTO products (id, name) VALUES ($1, $2)`, uuid.NewString(), name)
		if err != nil {
			t.Fatalf("seed duplicate product %q: %v", name, err)
		}
	}
	var rows int
	if err := n.pool.QueryRow(ctx,
		`SELECT count(*) FROM products WHERE lower(name) = lower($1)`, name).Scan(&rows); err != nil {
		t.Fatalf("count products named %q: %v", name, err)
	}
	if rows != 2 {
		t.Fatalf("products named %q = %d, want 2 — the name is not ambiguous, so the matrix's third case is not the case it claims", name, rows)
	}
}

// evidenceRows counts the evidence filed against a release and the distinct content
// fingerprints among them — "how many documents landed", asked of the table rather
// than inferred from a flag on a response.
func (n *botNode) evidenceRows(t *testing.T, releaseID string) (rows, fingerprints int) {
	t.Helper()
	err := n.pool.QueryRow(context.Background(),
		`SELECT count(*), count(DISTINCT fingerprint) FROM evidence WHERE subject_release_id = $1`,
		releaseID).Scan(&rows, &fingerprints)
	if err != nil {
		t.Fatalf("count evidence for %s: %v", releaseID, err)
	}
	return rows, fingerprints
}

// evidenceBuildID reads what was FILED, which is the half of B5's asymmetry no API
// surfaces: a receipt reports the attempt, the row reports the document.
func (n *botNode) evidenceBuildID(t *testing.T, evidenceID string) string {
	t.Helper()
	var buildID string
	err := n.pool.QueryRow(context.Background(),
		`SELECT provenance_build_id FROM evidence WHERE id = $1`, evidenceID).Scan(&buildID)
	if err != nil {
		t.Fatalf("read provenance_build_id of %s: %v", evidenceID, err)
	}
	return buildID
}

// --- the two write doors ---------------------------------------------------

// intake submits one request to the intake door and returns the status and the RAW
// body — raw, because byte-equality is the property 4.3 asserts and a decoded struct
// cannot carry it.
func (n *botNode) intake(t *testing.T, key string, query url.Values, contentType, body string) (int, []byte) {
	t.Helper()
	status, raw, err := botDo(context.Background(), http.MethodPost,
		n.evidence.URL+"/api/v1/intake?"+query.Encode(), key, contentType, body)
	if err != nil {
		t.Fatalf("POST /intake?%s: %v", query.Encode(), err)
	}
	return status, raw
}

// registerEvidence submits one request to the OLD door, `POST /evidence`, whose
// envelope carries the document as a JSON string.
func (n *botNode) registerEvidence(t *testing.T, key, releaseID, document string) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"kind":               "sbom",
		"format":             "cyclonedx",
		"subject_release_id": releaseID,
		"document":           document,
	})
	if err != nil {
		t.Fatalf("marshal evidence envelope: %v", err)
	}
	status, resp, err := botDo(context.Background(), http.MethodPost,
		n.evidence.URL+"/api/v1/evidence", key, "application/json", string(raw))
	if err != nil {
		t.Fatalf("POST /evidence: %v", err)
	}
	return status, resp
}

// --- wire helpers ----------------------------------------------------------

// botDo performs one request with an API key and returns status + body. It takes no
// *testing.T, so it is safe to call from the concurrency test's goroutines, and it is
// context-bound, so a wedged node fails the test rather than hanging the suite.
func botDo(ctx context.Context, method, target, key, contentType, body string) (int, []byte, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if key != "" {
		req.Header.Set(auth.APIKeyHeader, key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, raw, nil
}

// botTriple names a release the way a bot does: by the whole {product, project,
// version} triple.
func botTriple(product, project, version string) url.Values {
	return url.Values{"product": {product}, "project": {project}, "version": {version}}
}

// botWith copies a query and sets key/value pairs on the copy, so a shared triple is
// never mutated by the case that borrows it.
func botWith(base url.Values, kv ...string) url.Values {
	if len(kv)%2 != 0 {
		panic("botWith: key/value pairs must come in twos")
	}
	out := url.Values{}
	for k, vs := range base {
		out[k] = append([]string(nil), vs...)
	}
	for i := 0; i < len(kv); i += 2 {
		out.Set(kv[i], kv[i+1])
	}
	return out
}

// botReceipt is the receipt as these tests read it. `status` is a STRING here, which
// is why a refusal needs its own type below: `IntakeProblem.status` is the HTTP code.
type botReceipt struct {
	Status         string `json:"status"`
	ReleaseID      string `json:"release_id"`
	EvidenceID     string `json:"evidence_id"`
	BuildID        string `json:"build_id"`
	DetectedKind   string `json:"detected_kind"`
	DetectedFormat string `json:"detected_format"`
	// Created is a POINTER because D12 distinguishes an explicit false from an absent
	// field: "nothing was created" and "nobody said" are different answers.
	Created *bool `json:"created"`
}

// botRefusal is an intake Problem: the reason from the closed taxonomy and its
// elaboration, read as TWO fields and never concatenated (the 2026-09-22 lesson).
type botRefusal struct {
	Title  string `json:"title"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

func botDecodeReceipt(t *testing.T, raw []byte) botReceipt {
	t.Helper()
	var out botReceipt
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode receipt from %s: %v", raw, err)
	}
	return out
}

func botDecodeRefusal(t *testing.T, raw []byte) botRefusal {
	t.Helper()
	var out botRefusal
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode refusal from %s: %v", raw, err)
	}
	return out
}

func botDecodeProblemTitle(t *testing.T, raw []byte) string {
	t.Helper()
	return botDecodeRefusal(t, raw).Title
}

// botUnauthorizedFields is the whole of what intake's non-disclosing `403` may carry:
// the fixed title, the status, the reason from the closed taxonomy and the resolver's
// one constant detail. Anything else is either an estate fact (which B3 forbids) or a
// per-request value (which would make the refusals distinguishable).
var botUnauthorizedFields = []string{"detail", "reason", "status", "title"}

// botFieldNames returns a JSON object's top-level keys, sorted.
func botFieldNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("decode object from %s: %v", raw, err)
	}
	names := make([]string, 0, len(obj))
	for k := range obj {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func botSameFields(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// --- database plumbing -----------------------------------------------------

// botDSN points the suite's DSN at another database on the same server.
func botDSN(t *testing.T, base, dbName string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse suite dsn: %v", err)
	}
	u.Path = "/" + dbName
	return u.String()
}

// botMigrate applies one migrations directory and checks it landed on the version the
// DIRECTORY says is current.
//
// An empty table name takes golang-migrate's default `schema_migrations`, and exactly
// one of this database's three schemas may do that (see the file comment). The check
// is what makes that safe rather than merely intended: two schemas sharing a
// bookkeeping table is a SILENT defect — the second reads the first's version, skips
// its own CREATEs and reports success — and it shows up here as an applied version
// that does not match the directory.
//
// The expected version is DERIVED from the directory and never written down, the same
// rule `scripts/vm-verify.sh` runs on (task 4.5): a literal would be right the day it
// was written and silently wrong after the next migration.
//
// A non-empty table name rides a SEPARATE DSN parameter: pgx forwards an unknown DSN
// parameter to Postgres, so leaving `x-migrations-table` on the pool's DSN would fail
// every runtime connection.
func botMigrate(t *testing.T, dsn, relPath, table string) {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", relPath))
	if err != nil {
		t.Fatalf("resolve %s: %v", relPath, err)
	}
	migrateDSN := dsn
	if table != "" {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse dsn: %v", err)
		}
		q := u.Query()
		q.Set("x-migrations-table", table)
		u.RawQuery = q.Encode()
		migrateDSN = u.String()
	}
	m, err := migrate.New("file://"+abs, migrateDSN)
	if err != nil {
		t.Fatalf("migrate.New %s: %v", relPath, err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate %s: %v", relPath, err)
	}
	version, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("version of %s: %v", relPath, err)
	}
	if dirty {
		t.Fatalf("%s is at version %d but DIRTY", relPath, version)
	}
	if want := botHighestMigration(t, abs); version != want {
		t.Fatalf("%s applied version %d, want %d (the highest *.up.sql on disk) — in a shared database this is the shape of two schemas using one bookkeeping table",
			relPath, version, want)
	}
}

// botHighestMigration is the numeric maximum `NNNNNN_` prefix among a directory's
// `*.up.sql` files — the same derivation `scripts/vm-verify.sh`'s check_migration
// performs in shell.
func botHighestMigration(t *testing.T, dir string) uint {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil {
		t.Fatalf("list migrations in %s: %v", dir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no *.up.sql files in %s", dir)
	}
	var highest uint
	for _, f := range files {
		name := filepath.Base(f)
		cut := strings.IndexByte(name, '_')
		if cut <= 0 {
			t.Fatalf("migration %q has no NNNNNN_ prefix", name)
		}
		n, err := strconv.ParseUint(name[:cut], 10, 64)
		if err != nil {
			t.Fatalf("migration %q has a non-numeric prefix: %v", name, err)
		}
		if uint(n) > highest {
			highest = uint(n)
		}
	}
	return highest
}

// botRegistrySeam is Evidence's registry seam, read and write, mirroring
// cmd/evidence's `registryReader` — reads, plus the ONE write B2 permits. It lives
// here rather than being imported because a composition root is a `main` package:
// the seam is assembled where two contexts legitimately meet, and that is the only
// place the registry's ambiguity sentinel is translated into Evidence's own.
type botRegistrySeam struct{ store *registrystore.Store }

func (s botRegistrySeam) ReleaseExists(ctx context.Context, releaseID string) (bool, error) {
	return s.store.ReleaseExists(ctx, releaseID)
}

func (s botRegistrySeam) ProductIDByName(ctx context.Context, name string) (string, error) {
	id, err := s.store.ProductIDByName(ctx, name)
	return id, botTranslateAmbiguous(err)
}

func (s botRegistrySeam) ProjectIDByName(ctx context.Context, productID, name string) (string, error) {
	id, err := s.store.ProjectIDByName(ctx, productID, name)
	return id, botTranslateAmbiguous(err)
}

func (s botRegistrySeam) ReleaseIDByVersion(ctx context.Context, projectID, version string) (string, error) {
	id, err := s.store.ReleaseIDByVersion(ctx, projectID, version)
	return id, botTranslateAmbiguous(err)
}

func (s botRegistrySeam) ProductOfRelease(ctx context.Context, releaseID string) (string, error) {
	return s.store.ProductOfRelease(ctx, releaseID)
}

func (s botRegistrySeam) UpsertRelease(ctx context.Context, projectID, version string) (string, bool, error) {
	return s.store.UpsertRelease(ctx, projectID, version)
}

func botTranslateAmbiguous(err error) error {
	if errors.Is(err, registryapp.ErrAmbiguousName) {
		return subjectref.ErrAmbiguousName
	}
	return err
}
