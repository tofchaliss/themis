package http_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/platform/auth"
)

// EXPLICIT write-scope authorization on the Governance write surface (EDR-DELIVERY-01 N-M0,
// runtime-side D-N-6). Until this existed, every mutation was authorized by
// `auth.Principal.AuthorizeWrite()`, which sees a principal and no resource: it could not
// confine `product:<id>` to that product's Findings (the gap EDR-SECURITY-01 D4's realization
// note opened and EDR-HARNESS-01 D4 carried), and it granted write to ANY scope that was not
// `read` — including a `delivery:callback` credential handed to an outward delivery target.
//
// The matrix below is the guarantee stated as a test: every write route × every scope. It is
// written as a matrix on purpose — a per-route hand-written check is how one route gets added
// later with no gate on it.

// authzServer serves the Governance router behind an injected principal whose scopes the test
// may change between requests (so a case can SET UP as admin and then act as the scope under
// test), with the Registry product seam stubbed.
func authzServer(t *testing.T, repo *fakeRepo, products govhttp.ProductResolver, scopes *[]string) *httptest.Server {
	t.Helper()
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(fakeAdvisor{
		produced: true,
		rec:      app.Recommendation{Stance: "affected", Confidence: 0.9, Reasoning: "KEV-listed", Capability: "recommend_position@v1"},
	})
	read := app.NewReadService(repo, fakeProjection{}, nil, 0)
	h := govhttp.NewHandler(write, read)
	if products != nil {
		h = h.WithProductResolver(products)
	}
	router := h.Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k-1", Name: "test", Scopes: *scopes})
		router.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// idFrom pulls a minted id out of a 2xx setup response body.
func idFrom(t *testing.T, body []byte, field string) string {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("setup response %s: %v", body, err)
	}
	id, _ := out[field].(string)
	if id == "" {
		t.Fatalf("setup response carried no %s: %s", field, body)
	}
	return id
}

// writeRoute is one gated mutation: its setup (run as admin) yields the path, and `success` is
// what the route answers when the principal IS authorized.
type writeRoute struct {
	name    string
	setup   func(t *testing.T, srv *httptest.Server) string
	body    map[string]any
	success int
}

func governanceWriteRoutes() []writeRoute {
	raise := func(t *testing.T, srv *httptest.Server) string {
		t.Helper()
		status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals", map[string]any{"stance": "affected"})
		if status != http.StatusCreated {
			t.Fatalf("setup raise: %d %s", status, body)
		}
		return "/findings/fnd-1/proposals/" + idFrom(t, body, "proposal_id")
	}
	return []writeRoute{
		{
			name:    "raise_proposal",
			setup:   func(*testing.T, *httptest.Server) string { return "/findings/fnd-1/proposals" },
			body:    map[string]any{"stance": "affected", "rationale": "confirmed"},
			success: http.StatusCreated,
		},
		{
			name:    "accept_proposal",
			setup:   func(t *testing.T, srv *httptest.Server) string { return raise(t, srv) + "/accept" },
			body:    map[string]any{},
			success: http.StatusNoContent,
		},
		{
			name:    "reject_proposal",
			setup:   func(t *testing.T, srv *httptest.Server) string { return raise(t, srv) + "/reject" },
			body:    map[string]any{},
			success: http.StatusNoContent,
		},
		{
			name:    "commission_finding",
			setup:   func(*testing.T, *httptest.Server) string { return "/findings/fnd-1/commissions" },
			body:    commissionBody(),
			success: http.StatusCreated,
		},
		{
			name: "withdraw_commission",
			setup: func(t *testing.T, srv *httptest.Server) string {
				t.Helper()
				status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/commissions", commissionBody())
				if status != http.StatusCreated {
					t.Fatalf("setup commission: %d %s", status, body)
				}
				return "/findings/fnd-1/commissions/" + idFrom(t, body, "commission_id") + "/withdraw"
			},
			body:    map[string]any{"rationale": "premise moved"},
			success: http.StatusNoContent,
		},
		{
			name:    "recommend_position",
			setup:   func(*testing.T, *httptest.Server) string { return "/findings/fnd-1/recommend" },
			success: http.StatusCreated,
		},
		{
			name:    "resolve_finding",
			setup:   func(*testing.T, *httptest.Server) string { return "/findings/fnd-1/resolve" },
			success: http.StatusNoContent,
		},
		{
			name: "reopen_finding",
			setup: func(t *testing.T, srv *httptest.Server) string {
				t.Helper()
				if status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/resolve", nil); status != http.StatusNoContent {
					t.Fatalf("setup resolve: %d %s", status, body)
				}
				return "/findings/fnd-1/reopen"
			},
			success: http.StatusNoContent,
		},
		{
			name:    "archive_finding",
			setup:   func(*testing.T, *httptest.Server) string { return "/findings/fnd-1/archive" },
			success: http.StatusNoContent,
		},
	}
}

// The matrix: every Governance write route × every scope. `product:prod-1` owns rel-1, which
// fnd-1 belongs to; `product:prod-2` is a legitimate key for somebody else's product.
func TestGovernanceWriteScopeMatrix(t *testing.T) {
	principals := []struct {
		name    string
		scopes  []string
		allowed bool
	}{
		{"read", []string{auth.ScopeRead}, false},
		{"delivery_callback", []string{auth.ScopeDeliveryCallback}, false},
		{"product_wrong", []string{auth.ProductScopePrefix + "prod-2"}, false},
		{"product_correct", []string{auth.ProductScopePrefix + "prod-1"}, true},
		{"admin", []string{auth.ScopeAdmin}, true},
	}
	for _, rt := range governanceWriteRoutes() {
		for _, pr := range principals {
			t.Run(rt.name+"/"+pr.name, func(t *testing.T) {
				repo := newRepo()
				repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
				scopes := []string{auth.ScopeAdmin}
				srv := authzServer(t, repo, stubProducts{byRelease: map[string]string{"rel-1": "prod-1"}}, &scopes)
				path := rt.setup(t, srv)

				scopes = pr.scopes // the identity under test takes over
				want := rt.success
				if !pr.allowed {
					want = http.StatusForbidden
				}
				status, body := do(t, http.MethodPost, srv.URL+path, rt.body)
				if status != want {
					t.Fatalf("POST %s as %v = %d, want %d: %s", path, pr.scopes, status, want, body)
				}
			})
		}
	}
}

// A refusal must leave NOTHING behind: the gate runs before the body is read, so a refused
// write cannot half-apply. Status-only assertions would pass even if it did.
func TestRefusedWriteRecordsNothing(t *testing.T) {
	for _, scopes := range [][]string{
		{auth.ScopeRead},
		{auth.ScopeDeliveryCallback},
		{auth.ProductScopePrefix + "prod-2"},
	} {
		repo := newRepo()
		repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
		s := scopes
		srv := authzServer(t, repo, stubProducts{byRelease: map[string]string{"rel-1": "prod-1"}}, &s)

		if status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals",
			map[string]any{"stance": "affected"}); status != http.StatusForbidden {
			t.Fatalf("%v raise = %d: %s", scopes, status, body)
		}
		if status, _ := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/commissions", commissionBody()); status != http.StatusForbidden {
			t.Fatalf("%v commission = %d", scopes, status)
		}
		f := repo.byID["fnd-1"]
		if len(f.Proposals()) != 0 || len(f.Commissions()) != 0 {
			t.Errorf("%v left state behind: %d proposals, %d commissions",
				scopes, len(f.Proposals()), len(f.Commissions()))
		}
	}
}

// A `delivery:callback` key is refused on the SCOPE, not on what is missing beside it: even
// carrying admin and the right product grant, it may not write to Governance. A credential that
// leaves the estate (M1's delivery targets hold it) must not double as a governance identity.
func TestDeliveryCallbackIsRefusedEvenAlongsideAdmin(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	scopes := []string{auth.ScopeAdmin, auth.ProductScopePrefix + "prod-1", auth.ScopeDeliveryCallback}
	srv := authzServer(t, repo, stubProducts{byRelease: map[string]string{"rel-1": "prod-1"}}, &scopes)

	status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals", map[string]any{"stance": "affected"})
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", status, body)
	}
	// And the middleware floor agrees: the scope alone is not write-capable anywhere.
	if (auth.Principal{Scopes: []string{auth.ScopeDeliveryCallback}}).AuthorizeWrite() {
		t.Error("delivery:callback must not satisfy the method-based write floor either")
	}
}

// Confinement is to the Finding's OWN product: one key, two Findings in two products. The read
// surface stays open to it — this is a write rule, not a tenancy model.
func TestProductScopeConfinedToItsOwnProductsFindings(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "mine", "rel-1", "fl-1", "CVE-1"))
	repo.seed(identified(t, "theirs", "rel-2", "fl-1", "CVE-1"))
	scopes := []string{auth.ProductScopePrefix + "prod-1"}
	srv := authzServer(t, repo, stubProducts{byRelease: map[string]string{
		"rel-1": "prod-1", "rel-2": "prod-2",
	}}, &scopes)

	if status, body := do(t, http.MethodPost, srv.URL+"/findings/mine/proposals",
		map[string]any{"stance": "affected"}); status != http.StatusCreated {
		t.Fatalf("own product = %d, want 201: %s", status, body)
	}
	if status, body := do(t, http.MethodPost, srv.URL+"/findings/theirs/proposals",
		map[string]any{"stance": "affected"}); status != http.StatusForbidden {
		t.Fatalf("other product = %d, want 403: %s", status, body)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/findings/theirs", nil); status != http.StatusOK {
		t.Error("reads must stay open: N-M0 confines writes, it does not partition the read API")
	}
}

// FAIL-CLOSED. An unverifiable confinement is not a confinement, so a product-scoped key is
// refused whenever the product cannot be established — Registry unreachable, the seam not wired
// on this node, or a release Registry does not know. Admin is deliberately unaffected: a node
// without the Registry seam must still be operable.
func TestWriteRefusedWhenProductCannotBeResolved(t *testing.T) {
	cases := []struct {
		name     string
		products govhttp.ProductResolver
	}{
		{"registry unreachable", stubProducts{err: errors.New("dial tcp: connection refused")}},
		{"release unknown to registry", stubProducts{byRelease: map[string]string{"rel-other": "prod-1"}}},
		{"seam not wired", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo()
			repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
			scopes := []string{auth.ProductScopePrefix + "prod-1"}
			srv := authzServer(t, repo, tc.products, &scopes)

			if status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals",
				map[string]any{"stance": "affected"}); status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", status, body)
			}
			scopes = []string{auth.ScopeAdmin}
			if status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals",
				map[string]any{"stance": "affected"}); status != http.StatusCreated {
				t.Fatalf("admin status = %d, want 201 (admin needs no product resolution): %s", status, body)
			}
		})
	}
}

// A write to a Finding that does not exist is 404, not 403: the resource is absent, and
// answering 403 would tell a product-scoped operator that their own Finding is someone else's.
func TestWriteToUnknownFindingIsNotFound(t *testing.T) {
	repo := newRepo()
	scopes := []string{auth.ProductScopePrefix + "prod-1"}
	srv := authzServer(t, repo, stubProducts{byRelease: map[string]string{"rel-1": "prod-1"}}, &scopes)

	if status, body := do(t, http.MethodPost, srv.URL+"/findings/ghost/proposals",
		map[string]any{"stance": "affected"}); status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", status, body)
	}
}

// A scope outside the closed vocabulary authorizes nothing. It used to authorize EVERY write:
// `AuthorizeWrite` granted on any grant that was not `read`, so a typo'd or invented scope was
// indistinguishable from admin at a write.
func TestUnknownScopeAuthorizesNothing(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	scopes := []string{"produc:prod-1", "governance:write", ""}
	srv := authzServer(t, repo, stubProducts{byRelease: map[string]string{"rel-1": "prod-1"}}, &scopes)

	if status, body := do(t, http.MethodPost, srv.URL+"/findings/fnd-1/proposals",
		map[string]any{"stance": "affected"}); status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", status, body)
	}
}
