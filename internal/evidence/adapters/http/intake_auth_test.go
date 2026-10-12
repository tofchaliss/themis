package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	evhttp "github.com/themis-project/themis/internal/evidence/adapters/http"
	"github.com/themis-project/themis/internal/evidence/adapters/http/gen"
	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// Product-scope authorization on both doors (EDR-INTAKE-01 B3/B7, EDR-SECURITY-01 D4).
//
// These tests wire the REAL intake use case, the REAL resolver and the REAL auth
// middleware over a fake registry, because what they assert is the BYTES a client
// receives: a fake use case can prove a handler returns `403`, and only the whole
// chain can prove that the three refusals a product-scoped key must not distinguish
// are the same response.

// The estate the fixture knows. `prod-1` owns `rel-1` through `proj-1`; `prod-other`
// owns `rel-other`; `twins` is a name that matches more than one product, which is
// reachable on an un-migrated estate and is B3's third indistinguishable outcome.
const (
	fxProduct     = "OAMP"
	fxProject     = "oamp-core"
	fxVersion     = "R1917.256"
	fxProductID   = "prod-1"
	fxOtherProdID = "prod-other"
	fxRelease     = "rel-1"
	fxOtherRel    = "rel-other"
	fxAmbiguous   = "TWINS"
	fxMissing     = "acquisition-target"

	// The SBOM body every request here submits: identified, never converted, so the
	// chain reaches the filing step without a converter in the way.
	fxBody = `{"bomFormat":"CycloneDX","specVersion":"1.5"}`
)

// authRegistry is the read seam, from maps. It counts the project hop so a test can
// assert it was never reached — "unreached" and "returned nothing" must not be the
// same test result.
type authRegistry struct {
	projectLookups int
	ownerLookups   int
}

func (a *authRegistry) ReleaseExists(_ context.Context, releaseID string) (bool, error) {
	return releaseID == fxRelease || releaseID == fxOtherRel, nil
}

func (a *authRegistry) ProductIDByName(_ context.Context, name string) (string, error) {
	switch name {
	case fxProduct:
		return fxProductID, nil
	case "OTHER":
		return fxOtherProdID, nil
	case fxAmbiguous:
		return "", subjectref.ErrAmbiguousName
	default:
		return "", nil
	}
}

func (a *authRegistry) ProjectIDByName(_ context.Context, productID, name string) (string, error) {
	a.projectLookups++
	if productID == fxProductID && name == fxProject {
		return "proj-1", nil
	}
	return "", nil
}

func (a *authRegistry) ReleaseIDByVersion(_ context.Context, projectID, version string) (string, error) {
	if projectID == "proj-1" && version == fxVersion {
		return fxRelease, nil
	}
	return "", nil
}

func (a *authRegistry) ProductOfRelease(_ context.Context, releaseID string) (string, error) {
	a.ownerLookups++
	switch releaseID {
	case fxRelease:
		return fxProductID, nil
	case fxOtherRel:
		return fxOtherProdID, nil
	default:
		return "", nil
	}
}

// sbomReports identifies every body as an SBOM: already a standards document, so the
// converter is never involved and the chain is the one under test and nothing else.
type sbomReports struct{}

func (sbomReports) Detect(string, []byte) (string, string, error) { return "sbom", "cyclonedx", nil }

func (sbomReports) Convert(string, []byte, time.Time) ([]byte, app.ReportStats, string, string, error) {
	return nil, app.ReportStats{}, "", "", errors.New("an SBOM is never converted")
}

type hasInventory struct{}

func (hasInventory) HasInventory(context.Context, string) (bool, error) { return true, nil }

type countingRegistrar struct{ calls int }

func (c *countingRegistrar) Register(context.Context, app.RegisterCommand) (app.RegisterResult, error) {
	c.calls++
	return app.RegisterResult{ID: "ev-1", Created: true}, nil
}

type authFixture struct {
	// authed is the door as cmd/evidence mounts it: inside the authenticated
	// /api/v1 group, behind RequireAPIKey and the method write floor.
	authed http.Handler
	// open is the SAME door on a node with auth disabled — no middleware, so no
	// principal on the context at all.
	open      http.Handler
	reg       *authRegistry
	registrar *countingRegistrar
}

// newAuthFixture wires both doors over the fake estate, twice: once behind the real
// inbound auth edge, once with none.
func newAuthFixture(t *testing.T) authFixture {
	t.Helper()
	reg := &authRegistry{}
	registrar := &countingRegistrar{}
	intakeSvc := app.NewIntakeService(0, subjectref.NewResolver(reg), hasInventory{}, sbomReports{}, registrar)
	intake := evhttp.NewIntake(intakeSvc, newReceipts(), nil, evhttp.IntakeConfig{InlineBudget: time.Minute}, nil)
	t.Cleanup(intake.Close)

	// The old door's own chain, so `POST /evidence` is exercised end to end too.
	svc := app.NewEvidenceService(
		stubTrust{out: acceptTrust()},
		stubParser{inv: inventory(t)},
		stubSubject{ok: true},
		&memRepo{byID: map[domain.EvidenceID]domain.Evidence{}, created: true},
		stubIDs{}, stubClock{},
	)
	door := evhttp.NewHandler(svc).WithIntake(intake).WithReleaseOwnership(reg).Router()

	authn := auth.Authenticator{
		Keys: fakeKeys{keys: []auth.APIKey{
			{ID: "k-admin", Name: "ci-admin", KeyHash: "hash-admin", Scopes: []string{auth.ScopeAdmin}},
			{ID: "k-mine", Name: "ci-oamp", KeyHash: "hash-mine", Scopes: []string{auth.ProductScopePrefix + fxProductID}},
			{ID: "k-read", Name: "viewer", KeyHash: "hash-read", Scopes: []string{auth.ScopeRead}},
			{ID: "k-cb", Name: "delivery", KeyHash: "hash-callback", Scopes: []string{auth.ScopeDeliveryCallback}},
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
		r.Mount("/api/v1", door)
	})
	open := chi.NewRouter()
	open.Mount("/api/v1", door)

	return authFixture{authed: router, open: open, reg: reg, registrar: registrar}
}

// response is one answer reduced to the three things B3 requires to be identical.
type response struct {
	code    int
	headers string
	body    string
}

func answer(rec *httptest.ResponseRecorder) response {
	var hdrs []string
	for k, v := range rec.Result().Header {
		hdrs = append(hdrs, k+": "+strings.Join(v, ","))
	}
	sort.Strings(hdrs)
	return response{code: rec.Code, headers: strings.Join(hdrs, "; "), body: rec.Body.String()}
}

func withKey(key string) map[string]string {
	return map[string]string{auth.APIKeyHeader: key}
}

func intakeByTriple(product string) string {
	return fmt.Sprintf("/api/v1/intake?product=%s&project=%s&version=%s", product, fxProject, fxVersion)
}

// --- the name path (task 2.6) -----------------------------------------------

// TestProductScopedKeyCannotDistinguishOtherExistingMissingOrAmbiguous is B3 stated as
// a property: the three outcomes of the product lookup that are not "resolves to
// exactly my own product" must be ONE response — equal as bytes, not merely all 403.
// Asserting "all three are 403" would pass while the detail text leaked the answer,
// and the leak is the whole defect: otherwise any holder of any product key can ask
// intake whether a product exists and read the answer off the status line.
func TestProductScopedKeyCannotDistinguishOtherExistingMissingOrAmbiguous(t *testing.T) {
	f := newAuthFixture(t)

	var answers []response
	for _, tc := range []struct{ name, product string }{
		{"resolves to another product", "OTHER"},
		{"resolves to nothing", fxMissing},
		{"is ambiguous", fxAmbiguous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, f.authed, intakeByTriple(tc.product), fxBody, withKey("mine"))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Reason == nil || *p.Reason != gen.Unauthorized {
				t.Errorf("reason = %v, want unauthorized", p.Reason)
			}
			// A fresh receipt id per request would make these bodies differ on the one
			// field a caller can replay against, so this response names none.
			if p.IntakeId != nil {
				t.Errorf("the refusal names receipt %q; a per-request id cannot be identical across the three outcomes", *p.IntakeId)
			}
			answers = append(answers, answer(rec))
		})
	}
	if f.registrar.calls != 0 {
		t.Errorf("a refused request filed something (%d register calls)", f.registrar.calls)
	}
	for i, got := range answers[1:] {
		if got != answers[0] {
			t.Errorf("response %d differs from the first:\n%+v\n%+v", i+1, answers[0], got)
		}
	}
}

// TestAdminIsTold404ForAMissingProductOrProject — the other side of B3: only an admin
// key is told which part missed, and that answer is unchanged. An operator with the
// authority to see the estate must not be made to guess.
func TestAdminIsTold404ForAMissingProductOrProject(t *testing.T) {
	f := newAuthFixture(t)

	for _, tc := range []struct {
		name, target, wantIn string
		wantStatus           int
		wantReason           gen.RejectReason
	}{
		{
			name: "a missing product", target: intakeByTriple(fxMissing),
			wantIn: `product named "` + fxMissing + `"`, wantStatus: http.StatusNotFound, wantReason: gen.UnknownRelease,
		},
		{
			name:   "a missing project",
			target: fmt.Sprintf("/api/v1/intake?product=%s&project=nope&version=%s", fxProduct, fxVersion),
			wantIn: `project named "nope"`, wantStatus: http.StatusNotFound, wantReason: gen.UnknownRelease,
		},
		{
			name: "an ambiguous product", target: intakeByTriple(fxAmbiguous),
			wantIn: "ambiguous", wantStatus: http.StatusUnprocessableEntity, wantReason: gen.AmbiguousName,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, f.authed, tc.target, fxBody, withKey("admin"))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body)
			}
			p := decodeProblem(t, rec)
			if p.Reason == nil || *p.Reason != tc.wantReason {
				t.Fatalf("reason = %v, want %q", p.Reason, tc.wantReason)
			}
			if !strings.Contains(p.Detail, tc.wantIn) {
				t.Errorf("detail %q does not name %q — an admin must not have to guess which part missed", p.Detail, tc.wantIn)
			}
		})
	}
}

// TestAuthorizationPrecedesTheProjectLookup — the ORDER, asserted through the door.
// A check placed after the project hop would leak project existence under a product
// the key may not see, by exactly the oracle the `403` closes.
func TestAuthorizationPrecedesTheProjectLookup(t *testing.T) {
	f := newAuthFixture(t)

	rec := post(t, f.authed, intakeByTriple("OTHER"), fxBody, withKey("mine"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body)
	}
	if f.reg.projectLookups != 0 {
		t.Errorf("the project was looked up %d time(s) for a key that may not see the product", f.reg.projectLookups)
	}
}

// TestAuthDisabledNodeTreatsTheCallerAsAdmin — on a node with
// `THEMIS_AUTH_DATABASE_DSN` unset there is no principal, so intake takes the same
// posture every other route on that node already has (B3). `THEMIS_AUTH_REQUIRED=1`
// remains the production guard; `create_release` does not touch the auth switch.
func TestAuthDisabledNodeTreatsTheCallerAsAdmin(t *testing.T) {
	f := newAuthFixture(t)

	if rec := post(t, f.open, intakeByTriple(fxProduct), fxBody, nil); rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body)
	}
	// And it is told which part missed, exactly as an admin is — not refused `403`.
	rec := post(t, f.open, intakeByTriple(fxMissing), fxBody, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body)
	}
	if f.reg.ownerLookups != 0 {
		t.Error("a caller with no principal paid for an ownership read whose answer cannot change the outcome")
	}
}

// TestReadAndCallbackScopesAreRefusedByTheWriteFloor — the method-based floor still
// sits below the product check and refuses both before the door is reached, so a
// read-only credential and a delivery callback credential can file nothing. Neither
// is a product-scope decision: they have no write capability at all.
func TestReadAndCallbackScopesAreRefusedByTheWriteFloor(t *testing.T) {
	f := newAuthFixture(t)

	for _, key := range []string{"read", "callback"} {
		t.Run(key, func(t *testing.T) {
			rec := post(t, f.authed, intakeByTriple(fxProduct), fxBody, withKey(key))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body)
			}
			// The floor's refusal, not the door's: it carries no intake reason,
			// because no attempt was ever made.
			var raw map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			if _, present := raw["reason"]; present {
				t.Errorf("the write floor's refusal carries an intake reason: %v", raw)
			}
			if f.registrar.calls != 0 {
				t.Errorf("a key refused by the write floor reached the filing step")
			}
		})
	}
}

// --- the release_id path, on BOTH doors (task 2.6b) -------------------------

// TestProductKeyCannotFileAgainstAnotherProductsRelease — the gap B7 closes. The
// `release_id` road rested on the method write floor, which sees a principal and no
// resource, so a `product:<A>` key could file evidence against product B's release
// just by naming its id. It is closed on both doors in the same change, because an
// old door that still accepts it is not an old door, it is a bypass.
func TestProductKeyCannotFileAgainstAnotherProductsRelease(t *testing.T) {
	f := newAuthFixture(t)

	t.Run("POST /intake", func(t *testing.T) {
		rec := post(t, f.authed, "/api/v1/intake?release_id="+fxOtherRel, fxBody, withKey("mine"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body)
		}
		if p := decodeProblem(t, rec); p.Reason == nil || *p.Reason != gen.Unauthorized {
			t.Errorf("reason = %v, want unauthorized", p.Reason)
		}
	})

	t.Run("POST /evidence", func(t *testing.T) {
		rec := post(t, f.authed, "/api/v1/evidence", registerBody(fxOtherRel), withKey("mine"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body)
		}
	})

	if f.registrar.calls != 0 {
		t.Errorf("a refused request filed something (%d register calls)", f.registrar.calls)
	}
}

// TestProductKeyCannotDistinguishForeignFromMissingReleaseID — B3 applied to ids
// exactly as to names (rows 17-18): if the two differed, a release id would be
// guessable by status code. Asserted as bytes on both doors.
func TestProductKeyCannotDistinguishForeignFromMissingReleaseID(t *testing.T) {
	f := newAuthFixture(t)

	for _, door := range []struct {
		name   string
		call   func(releaseID string) *httptest.ResponseRecorder
		target string
	}{
		{
			name: "POST /intake",
			call: func(releaseID string) *httptest.ResponseRecorder {
				return post(t, f.authed, "/api/v1/intake?release_id="+releaseID, fxBody, withKey("mine"))
			},
		},
		{
			name: "POST /evidence",
			call: func(releaseID string) *httptest.ResponseRecorder {
				return post(t, f.authed, "/api/v1/evidence", registerBody(releaseID), withKey("mine"))
			},
		},
	} {
		t.Run(door.name, func(t *testing.T) {
			foreign := answer(door.call(fxOtherRel))
			missing := answer(door.call("rel-does-not-exist"))
			if foreign.code != http.StatusForbidden {
				t.Fatalf("foreign release: status = %d, want 403 (%s)", foreign.code, foreign.body)
			}
			if foreign != missing {
				t.Errorf("the two refusals differ:\n%+v\n%+v", foreign, missing)
			}
		})
	}
}

// TestAdminStillGets404ForAMissingReleaseID — the only existing response this change
// moves is a product-scoped key's `404` on a nonexistent release, which becomes `403`.
// Admin and auth-disabled callers see no change at all, and that is asserted rather
// than assumed.
func TestAdminStillGets404ForAMissingReleaseID(t *testing.T) {
	f := newAuthFixture(t)

	rec := post(t, f.authed, "/api/v1/intake?release_id=rel-does-not-exist", fxBody, withKey("admin"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body)
	}
	p := decodeProblem(t, rec)
	if p.Reason == nil || *p.Reason != gen.UnknownRelease {
		t.Fatalf("reason = %v, want unknown_release", p.Reason)
	}
	if p.IntakeId == nil {
		t.Error("an ordinary refusal names no receipt; every intake is addressable (D9)")
	}
	if f.reg.ownerLookups != 0 {
		t.Error("an admin paid for an ownership read whose answer cannot change the outcome")
	}

	// The old door: B7 gives it the ownership check and nothing else, so for an admin
	// the existence answer stays whatever the door's own SubjectRef validation gives
	// (in production `422 unknown subject release`; this fixture's SubjectRef accepts
	// every id, which is why the status itself is not asserted here). What IS asserted
	// is that the new check never fires for an admin: no 403, and no ownership read.
	before := f.reg.ownerLookups
	old := post(t, f.authed, "/api/v1/evidence", registerBody("rel-does-not-exist"), withKey("admin"))
	if old.Code == http.StatusForbidden {
		t.Fatalf("POST /evidence as admin got the product-scope 403: %s", old.Body)
	}
	if f.reg.ownerLookups != before {
		t.Error("the old door paid for an ownership read for an admin")
	}
}

// TestProductKeyFilesAgainstItsOwnRelease — the confinement has to permit as well as
// refuse. A key scoped to the product that owns the release files on both doors.
func TestProductKeyFilesAgainstItsOwnRelease(t *testing.T) {
	f := newAuthFixture(t)

	if rec := post(t, f.authed, "/api/v1/intake?release_id="+fxRelease, fxBody, withKey("mine")); rec.Code != http.StatusCreated {
		t.Fatalf("POST /intake: status = %d, want 201: %s", rec.Code, rec.Body)
	}
	if rec := post(t, f.authed, intakeByTriple(fxProduct), fxBody, withKey("mine")); rec.Code != http.StatusCreated {
		t.Fatalf("POST /intake by triple: status = %d, want 201: %s", rec.Code, rec.Body)
	}
	if rec := post(t, f.authed, "/api/v1/evidence", registerBody(fxRelease), withKey("mine")); rec.Code != http.StatusCreated {
		t.Fatalf("POST /evidence: status = %d, want 201: %s", rec.Code, rec.Body)
	}
}

func registerBody(releaseID string) string {
	return fmt.Sprintf(`{"kind":"sbom","format":"cyclonedx","subject_release_id":%q,"document":"{}"}`, releaseID)
}
