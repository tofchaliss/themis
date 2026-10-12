package subjectref_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/domain"
)

// fakeRegistry answers the read seam from maps. A missing name is an empty id and a
// nil error, which is the seam's contract: "not found" is an answer, not a fault.
type fakeRegistry struct {
	releases map[string]bool
	products map[string]string            // product name -> id
	projects map[string]map[string]string // product id -> project name -> id
	versions map[string]map[string]string // project id -> version -> release id
	err      error
	failOn   string // which method returns err: "exists", "product", "project", "release"
}

func (f fakeRegistry) ReleaseExists(_ context.Context, id string) (bool, error) {
	if f.failOn == "exists" {
		return false, f.err
	}
	return f.releases[id], nil
}

func (f fakeRegistry) ProductIDByName(_ context.Context, name string) (string, error) {
	if f.failOn == "product" {
		return "", f.err
	}
	return f.products[name], nil
}

func (f fakeRegistry) ProjectIDByName(_ context.Context, productID, name string) (string, error) {
	if f.failOn == "project" {
		return "", f.err
	}
	return f.projects[productID][name], nil
}

func (f fakeRegistry) ReleaseIDByVersion(_ context.Context, projectID, version string) (string, error) {
	if f.failOn == "release" {
		return "", f.err
	}
	return f.versions[projectID][version], nil
}

func estate() fakeRegistry {
	return fakeRegistry{
		releases: map[string]bool{"rel-1": true},
		products: map[string]string{"OAMP": "prod-1"},
		projects: map[string]map[string]string{"prod-1": {"oamp-core": "proj-1"}},
		versions: map[string]map[string]string{"proj-1": {"R1917.256": "rel-1"}},
	}
}

func TestResolve_BothRoadsReachTheSameRelease(t *testing.T) {
	r := subjectref.NewResolver(estate())

	byID, err := r.Resolve(context.Background(), "", "", "", "rel-1")
	if err != nil || byID != "rel-1" {
		t.Fatalf("by id = %q, %v", byID, err)
	}
	byTriple, err := r.Resolve(context.Background(), "OAMP", "oamp-core", "R1917.256", "")
	if err != nil || byTriple != "rel-1" {
		t.Fatalf("by triple = %q, %v", byTriple, err)
	}
}

// TestResolve_ReleaseIDWinsOverTheTriple — the direct road is decisive, so a client
// that has the id never pays for three lookups, and a stale triple left in a script
// cannot quietly redirect an upload.
func TestResolve_ReleaseIDWinsOverTheTriple(t *testing.T) {
	reg := estate()
	reg.products = map[string]string{} // the triple would not resolve at all
	got, err := subjectref.NewResolver(reg).Resolve(context.Background(), "OAMP", "oamp-core", "R1917.256", "rel-1")
	if err != nil || got != "rel-1" {
		t.Fatalf("got %q, %v", got, err)
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
			got, err := r.Resolve(context.Background(), c.product, c.project, c.version, c.relID)
			if got != "" {
				t.Errorf("resolved %q, want nothing", got)
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
			_, err := subjectref.NewResolver(reg).Resolve(context.Background(), c.product, c.project, c.version, c.relID)
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

			got, err := subjectref.NewResolver(reg).Resolve(context.Background(), "OAMP", "oamp-core", "R1917.256", "")
			if got != "" {
				t.Errorf("resolved %q, want nothing", got)
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
	_, err := subjectref.NewResolver(estate()).Resolve(context.Background(), "NOPE", "oamp-core", "R1917.256", "")
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

// TestStub_KnowsIDsAndNoNames pins the dev stub's honest limit: it holds release ids,
// so the triple road reports unknown_release instead of resolving onto whichever
// release happened to be in the allow-set.
func TestStub_KnowsIDsAndNoNames(t *testing.T) {
	stub := subjectref.NewStub("rel-dev")
	r := subjectref.NewResolver(stub)

	if got, err := r.Resolve(context.Background(), "", "", "", "rel-dev"); err != nil || got != "rel-dev" {
		t.Fatalf("by id = %q, %v", got, err)
	}
	if _, err := r.Resolve(context.Background(), "OAMP", "oamp-core", "R1", ""); err == nil {
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
