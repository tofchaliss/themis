package subjectref_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
)

// fakeRegistry answers the read seam from maps. A missing name is an empty id and a
// nil error, which is the seam's contract: "not found" is an answer, not a fault.
type fakeRegistry struct {
	releases map[string]bool
	products map[string]string            // product name -> id
	projects map[string]map[string]string // product id -> project name -> id
	versions map[string]map[string]string // project id -> version -> release id
	owners   map[string]string            // release id -> owning product id
	err      error
	failOn   string // which method returns err: "exists", "product", "project", "release", "owner"

	// projectLookups counts the project hop, so a test can assert it was never
	// reached — "unreached" and "returned nothing" must not be the same result.
	projectLookups int
}

func (f *fakeRegistry) ReleaseExists(_ context.Context, id string) (bool, error) {
	if f.failOn == "exists" {
		return false, f.err
	}
	return f.releases[id], nil
}

func (f *fakeRegistry) ProductIDByName(_ context.Context, name string) (string, error) {
	if f.failOn == "product" {
		return "", f.err
	}
	return f.products[name], nil
}

func (f *fakeRegistry) ProjectIDByName(_ context.Context, productID, name string) (string, error) {
	f.projectLookups++
	if f.failOn == "project" {
		return "", f.err
	}
	return f.projects[productID][name], nil
}

func (f *fakeRegistry) ReleaseIDByVersion(_ context.Context, projectID, version string) (string, error) {
	if f.failOn == "release" {
		return "", f.err
	}
	return f.versions[projectID][version], nil
}

func (f *fakeRegistry) ProductOfRelease(_ context.Context, releaseID string) (string, error) {
	if f.failOn == "owner" {
		return "", f.err
	}
	return f.owners[releaseID], nil
}

func estate() *fakeRegistry {
	return &fakeRegistry{
		releases: map[string]bool{"rel-1": true},
		products: map[string]string{"OAMP": "prod-1"},
		projects: map[string]map[string]string{"prod-1": {"oamp-core": "proj-1"}},
		versions: map[string]map[string]string{"proj-1": {"R1917.256": "rel-1"}},
		owners:   map[string]string{"rel-1": "prod-1"},
	}
}

// byTriple and byID are the two roads as an unconfined caller (admin, or an
// auth-disabled node) travels them: no authorizer, which is the explicit statement
// that no product confinement applies.
func byTriple(product, project, version string) app.ResolveRequest {
	return app.ResolveRequest{Product: product, Project: project, Version: version}
}

func byID(releaseID string) app.ResolveRequest {
	return app.ResolveRequest{ReleaseID: releaseID}
}

// scopedTo is a `product:<id>` key's confinement: it authorizes that product and
// nothing else, exactly as auth.Principal.AuthorizeProduct does for such a key.
func scopedTo(productID string) app.ProductAuthorizer {
	return func(id string) bool { return id == productID }
}

func TestResolve_BothRoadsReachTheSameRelease(t *testing.T) {
	r := subjectref.NewResolver(estate())

	byRelease, err := r.Resolve(context.Background(), byID("rel-1"))
	if err != nil || byRelease.ReleaseID != "rel-1" || byRelease.ToCreate() {
		t.Fatalf("by id = %+v, %v", byRelease, err)
	}
	byName, err := r.Resolve(context.Background(), byTriple("OAMP", "oamp-core", "R1917.256"))
	if err != nil || byName.ReleaseID != "rel-1" || byName.ToCreate() {
		t.Fatalf("by triple = %+v, %v", byName, err)
	}
}

// TestResolve_ReleaseIDWinsOverTheTriple — the direct road is decisive, so a client
// that has the id never pays for three lookups, and a stale triple left in a script
// cannot quietly redirect an upload.
func TestResolve_ReleaseIDWinsOverTheTriple(t *testing.T) {
	reg := estate()
	reg.products = map[string]string{} // the triple would not resolve at all
	got, err := subjectref.NewResolver(reg).Resolve(context.Background(),
		app.ResolveRequest{Product: "OAMP", Project: "oamp-core", Version: "R1917.256", ReleaseID: "rel-1"})
	if err != nil || got.ReleaseID != "rel-1" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// TestResolve_RefusalsNameWhichPartMissed is the point of the three-step walk:
// "unknown release" on a three-part name leaves the operator guessing which part they
// got wrong, and the guess is the expensive bit.
func TestResolve_RefusalsNameWhichPartMissed(t *testing.T) {
	cases := []struct {
		name                             string
		product, project, version, relID string
		wantIn                           string
	}{
		{"unregistered release id", "", "", "", "rel-nope", `"rel-nope"`},
		{"unknown product", "NOPE", "oamp-core", "R1917.256", "", `product named "NOPE"`},
		{"unknown project", "OAMP", "nope", "R1917.256", "", `project named "nope"`},
		{"unknown version", "OAMP", "oamp-core", "R0.0", "", `release version named "R0.0"`},
		{"nothing named at all", "", "", "", "", "release_id"},
		{"a partial triple", "OAMP", "", "R1917.256", "", "triple"},
	}
	r := subjectref.NewResolver(estate())
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := r.Resolve(context.Background(),
				app.ResolveRequest{Product: c.product, Project: c.project, Version: c.version, ReleaseID: c.relID})
			if got != (app.Resolution{}) {
				t.Errorf("resolved %+v, want nothing", got)
			}
			re, ok := domain.AsReject(err)
			if !ok {
				t.Fatalf("error = %v, want a reason-carrying refusal", err)
			}
			if re.Reason != domain.ReasonUnknownRelease {
				t.Errorf("reason = %q, want unknown_release", re.Reason)
			}
			if !strings.Contains(re.Detail, c.wantIn) {
				t.Errorf("detail %q does not name %q", re.Detail, c.wantIn)
			}
		})
	}
}

// TestResolve_ALookupThatFailedIsNotAnUnknownRelease — a seam that could not be READ
// says nothing about whether the release exists. Reporting unknown_release here would
// tell the operator to register a release they already registered, so the error
// passes through carrying no reason at all (which the intake then reports as a
// failure, not a refusal).
func TestResolve_ALookupThatFailedIsNotAnUnknownRelease(t *testing.T) {
	boom := errors.New("connection refused")
	cases := []struct {
		failOn                           string
		product, project, version, relID string
	}{
		{"exists", "", "", "", "rel-1"},
		{"product", "OAMP", "oamp-core", "R1917.256", ""},
		{"project", "OAMP", "oamp-core", "R1917.256", ""},
		{"release", "OAMP", "oamp-core", "R1917.256", ""},
	}
	for _, c := range cases {
		t.Run(c.failOn, func(t *testing.T) {
			reg := estate()
			reg.err, reg.failOn = boom, c.failOn
			_, err := subjectref.NewResolver(reg).Resolve(context.Background(),
				app.ResolveRequest{Product: c.product, Project: c.project, Version: c.version, ReleaseID: c.relID})
			if !errors.Is(err, boom) {
				t.Fatalf("error = %v, want the cause to survive", err)
			}
			if _, ok := domain.AsReject(err); ok {
				t.Error("an unreadable seam was reported as a refusal; it is an infrastructure fault")
			}
		})
	}
}

// TestResolveAmbiguousNameIsNotReportedAsNotRegistered — a name that matches more than
// one row is a statement about the NAME, not the estate (EDR-INTAKE-01 B4). Reporting it
// as unknown_release says "no product named X is registered" about a product that is
// registered twice, and sends the operator hunting for a typo that is not there. The
// assertion is therefore two-part: the closed reason is `ambiguous_name`, AND the prose
// does not reuse the not-registered wording a consumer reads past the reason.
func TestResolveAmbiguousNameIsNotReportedAsNotRegistered(t *testing.T) {
	cases := []struct {
		failOn string
		wantIn string
	}{
		{"product", `product "OAMP"`},
		{"project", `project "oamp-core"`},
		{"release", `release version "R1917.256"`},
	}
	for _, c := range cases {
		t.Run(c.failOn, func(t *testing.T) {
			reg := estate()
			reg.err, reg.failOn = subjectref.ErrAmbiguousName, c.failOn

			got, err := subjectref.NewResolver(reg).Resolve(context.Background(), byTriple("OAMP", "oamp-core", "R1917.256"))
			if got != (app.Resolution{}) {
				t.Errorf("resolved %+v, want nothing", got)
			}
			re, ok := domain.AsReject(err)
			if !ok {
				t.Fatalf("error = %v, want a reason-carrying refusal: an abstention is an answer, not a fault", err)
			}
			if re.Reason != domain.ReasonAmbiguousName {
				t.Errorf("reason = %q, want %q", re.Reason, domain.ReasonAmbiguousName)
			}
			if strings.Contains(re.Detail, "not registered") {
				t.Errorf("detail %q says the name is not registered; it is registered more than once", re.Detail)
			}
			if !strings.Contains(re.Detail, "ambiguous") {
				t.Errorf("detail %q does not say the name is ambiguous", re.Detail)
			}
			if !strings.Contains(re.Detail, c.wantIn) {
				t.Errorf("detail %q does not name %q — the operator still has to guess which part", re.Detail, c.wantIn)
			}
		})
	}
}

// TestResolve_NotFoundWordingIsUnchanged guards the other half of B4's distinction: zero
// matches keeps the reason and the wording it has always had. The ambiguous branch is a
// third answer beside it, not a replacement for it.
func TestResolve_NotFoundWordingIsUnchanged(t *testing.T) {
	_, err := subjectref.NewResolver(estate()).Resolve(context.Background(), byTriple("NOPE", "oamp-core", "R1917.256"))
	re, ok := domain.AsReject(err)
	if !ok {
		t.Fatalf("error = %v, want a refusal", err)
	}
	if re.Reason != domain.ReasonUnknownRelease {
		t.Errorf("reason = %q, want unknown_release", re.Reason)
	}
	if re.Detail != `no product named "NOPE" is registered` {
		t.Errorf("detail = %q, want the unchanged not-found wording", re.Detail)
	}
}

// TestResolveToCreateOnMissingVersion — the ONE answer `create_release=true` changes
// (EDR-INTAKE-01 B2, B7's step 4): an absent version under a Product and Project that
// resolved comes back as "to be created", naming the project, instead of
// `unknown_release`. Resolution still writes nothing — the create is a later step, and
// every other answer here is unchanged, which the subtests assert one at a time
// because "create_release resolves differently" asserted once would pass with the
// product and project guards gone.
func TestResolveToCreateOnMissingVersion(t *testing.T) {
	ctx := context.Background()
	newVersion := func() app.ResolveRequest {
		return app.ResolveRequest{Product: "OAMP", Project: "oamp-core", Version: "R1918.001", CreateRelease: true}
	}

	got, err := subjectref.NewResolver(estate()).Resolve(ctx, newVersion())
	if err != nil {
		t.Fatalf("error = %v, want the absent version reported as an answer", err)
	}
	if !got.ToCreate() {
		t.Fatalf("resolved %+v, want a version still to be created", got)
	}
	if got.ProjectID != "proj-1" || got.Version != "R1918.001" {
		t.Errorf("to create = %+v, want the resolved project and the submitted version, so the create needs no second lookup", got)
	}

	t.Run("without create_release the same request is unchanged", func(t *testing.T) {
		req := newVersion()
		req.CreateRelease = false
		_, err := subjectref.NewResolver(estate()).Resolve(ctx, req)
		re, ok := domain.AsReject(err)
		if !ok || re.Reason != domain.ReasonUnknownRelease {
			t.Fatalf("error = %v, want the unchanged unknown_release", err)
		}
	})

	t.Run("a version that exists is resolved, never re-created", func(t *testing.T) {
		req := newVersion()
		req.Version = "R1917.256"
		got, err := subjectref.NewResolver(estate()).Resolve(ctx, req)
		if err != nil || got.ReleaseID != "rel-1" || got.ToCreate() {
			t.Fatalf("got %+v, %v, want the existing release", got, err)
		}
	})

	t.Run("a missing product or project is still a refusal, never a creation", func(t *testing.T) {
		for _, tc := range []struct{ name, product, project, wantIn string }{
			{"product", "NOPE", "oamp-core", `product named "NOPE"`},
			{"project", "OAMP", "nope", `project named "nope"`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req := newVersion()
				req.Product, req.Project = tc.product, tc.project
				got, err := subjectref.NewResolver(estate()).Resolve(ctx, req)
				if got != (app.Resolution{}) {
					t.Errorf("resolved %+v, want nothing: those names are human-owned and a typo in one is where a parallel estate comes from", got)
				}
				re, ok := domain.AsReject(err)
				if !ok || re.Reason != domain.ReasonUnknownRelease {
					t.Fatalf("error = %v, want unknown_release", err)
				}
				if !strings.Contains(re.Detail, tc.wantIn) {
					t.Errorf("detail %q does not name %q", re.Detail, tc.wantIn)
				}
			})
		}
	})

	t.Run("an unauthorized product is refused before any of it", func(t *testing.T) {
		req := newVersion()
		req.Authorize = scopedTo("prod-other")
		reg := estate()
		got, err := subjectref.NewResolver(reg).Resolve(ctx, req)
		if got != (app.Resolution{}) {
			t.Errorf("resolved %+v for a key that may not see the product", got)
		}
		if re, ok := domain.AsReject(err); !ok || re.Reason != domain.ReasonUnauthorized {
			t.Fatalf("error = %v, want an unauthorized refusal", err)
		}
		if reg.projectLookups != 0 {
			t.Error("`create_release` moved the authorization check: the project was looked up for a key that may not see the product")
		}
	})
}

// TestStub_KnowsIDsAndNoNames pins the dev stub's honest limit: it holds release ids,
// so the triple road reports unknown_release instead of resolving onto whichever
// release happened to be in the allow-set.
func TestStub_KnowsIDsAndNoNames(t *testing.T) {
	stub := subjectref.NewStub("rel-dev")
	r := subjectref.NewResolver(stub)

	if got, err := r.Resolve(context.Background(), byID("rel-dev")); err != nil || got.ReleaseID != "rel-dev" {
		t.Fatalf("by id = %+v, %v", got, err)
	}
	if _, err := r.Resolve(context.Background(), byTriple("OAMP", "oamp-core", "R1")); err == nil {
		t.Error("the stub resolved a triple it cannot know")
	}

	// Asserted directly as well, because the resolver gives up at the first miss and
	// would never call the later two — and "unreached" and "returns something" must
	// not be the same test result.
	for _, lookup := range []struct {
		name string
		call func() (string, error)
	}{
		{"product", func() (string, error) { return stub.ProductIDByName(context.Background(), "OAMP") }},
		{"project", func() (string, error) { return stub.ProjectIDByName(context.Background(), "prod-1", "oamp-core") }},
		{"release", func() (string, error) { return stub.ReleaseIDByVersion(context.Background(), "proj-1", "R1") }},
	} {
		id, err := lookup.call()
		if id != "" || err != nil {
			t.Errorf("%s lookup = %q, %v; want an empty id and no error", lookup.name, id, err)
		}
	}
}
