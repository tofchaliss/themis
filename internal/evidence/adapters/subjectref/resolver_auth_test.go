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

// Authorization on the read seam: the ORDER, and the non-leak (EDR-INTAKE-01 B3/B7).
// It is tested here, beside resolution, because that is where it happens — the
// decision needs the resolved product, and a check one ring further out could only
// ask the question before the answer existed.

// TestResolve_ProductScopedKeyCannotDistinguishTheProductLookupsOutcomes — B3 as a
// property rather than as a list of cases: for a `product:<P>` key, every outcome of
// the product lookup that is not "resolves to exactly my own product" is the SAME
// refusal, reason and detail included. Otherwise intake is a product-name oracle for
// any holder of any product key — name somebody's acquisition target and read the
// status code.
//
// A lookup that could not be PERFORMED joins them for a confined caller: an
// unverifiable confinement is not a confinement, which is the fail-closed rule
// Governance's write gate already runs on.
func TestResolve_ProductScopedKeyCannotDistinguishTheProductLookupsOutcomes(t *testing.T) {
	var details []string
	for _, tc := range []struct {
		name    string
		product string
		seed    func(*fakeRegistry)
	}{
		{name: "resolves to another product", product: "OAMP"},
		{name: "resolves to nothing", product: "acquisition-target"},
		{
			name:    "is ambiguous",
			product: "OAMP",
			seed:    func(f *fakeRegistry) { f.err, f.failOn = subjectref.ErrAmbiguousName, "product" },
		},
		{
			name:    "could not be read at all",
			product: "OAMP",
			seed:    func(f *fakeRegistry) { f.err, f.failOn = errors.New("connection refused"), "product" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := estate()
			if tc.seed != nil {
				tc.seed(reg)
			}
			got, err := subjectref.NewResolver(reg).Resolve(context.Background(), app.ResolveRequest{
				Product: tc.product, Project: "oamp-core", Version: "R1917.256",
				Authorize: scopedTo("prod-other"),
			})
			if got != (app.Resolution{}) {
				t.Errorf("resolved %+v, want nothing", got)
			}
			re, ok := domain.AsReject(err)
			if !ok {
				t.Fatalf("error = %v, want a reason-carrying refusal", err)
			}
			if re.Reason != domain.ReasonUnauthorized {
				t.Fatalf("reason = %q, want unauthorized", re.Reason)
			}
			// The estate must not appear in the one surface an unauthorized caller is
			// guaranteed to read.
			for _, leaked := range []string{tc.product, "prod-1", "ambiguous", "not registered", "connection refused"} {
				if strings.Contains(re.Detail, leaked) {
					t.Errorf("detail %q names %q, which the caller was refused permission to ask about", re.Detail, leaked)
				}
			}
			details = append(details, re.Detail)
		})
	}
	for _, d := range details[1:] {
		if d != details[0] {
			t.Errorf("the refusals differ:\n%q\n%q\nthey must be one string, or the status code becomes an oracle", details[0], d)
		}
	}
}

// TestResolve_AuthorizationPrecedesTheProjectLookup — the ORDER is the decision (B3).
// Putting the check after the project hop would leak project existence under a product
// the key may not see, by exactly the oracle the `403` closes.
func TestResolve_AuthorizationPrecedesTheProjectLookup(t *testing.T) {
	reg := estate()
	_, err := subjectref.NewResolver(reg).Resolve(context.Background(), app.ResolveRequest{
		Product: "OAMP", Project: "oamp-core", Version: "R1917.256",
		Authorize: scopedTo("prod-other"),
	})
	if re, ok := domain.AsReject(err); !ok || re.Reason != domain.ReasonUnauthorized {
		t.Fatalf("error = %v, want an unauthorized refusal", err)
	}
	if reg.projectLookups != 0 {
		t.Errorf("the project was looked up %d time(s) for a key that may not see the product", reg.projectLookups)
	}
}

// TestResolve_AnAuthorizedProductKeyGetsTheAnswersAnAdminGets — the other half of B3:
// once a key holds authority over the product there is nothing left to leak, so the
// project and the version answer exactly as they do for an admin.
func TestResolve_AnAuthorizedProductKeyGetsTheAnswersAnAdminGets(t *testing.T) {
	mine := scopedTo("prod-1")

	got, err := subjectref.NewResolver(estate()).Resolve(context.Background(), app.ResolveRequest{
		Product: "OAMP", Project: "oamp-core", Version: "R1917.256", Authorize: mine,
	})
	if err != nil || got.ReleaseID != "rel-1" {
		t.Fatalf("own product = %+v, %v, want the release", got, err)
	}

	for _, tc := range []struct {
		name, project, version string
		wantReason             domain.RejectReason
		wantIn                 string
	}{
		{"a missing project", "nope", "R1917.256", domain.ReasonUnknownRelease, `project named "nope"`},
		{"a missing version", "oamp-core", "R0.0", domain.ReasonUnknownRelease, `release version named "R0.0"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := subjectref.NewResolver(estate()).Resolve(context.Background(), app.ResolveRequest{
				Product: "OAMP", Project: tc.project, Version: tc.version, Authorize: mine,
			})
			re, ok := domain.AsReject(err)
			if !ok || re.Reason != tc.wantReason {
				t.Fatalf("error = %v, want %q", err, tc.wantReason)
			}
			if !strings.Contains(re.Detail, tc.wantIn) {
				t.Errorf("detail %q does not name %q", re.Detail, tc.wantIn)
			}
		})
	}
}

// TestResolve_ReleaseIDPathAuthorizesTheOwningProduct — B7 on the direct road, and
// rows 17-18's non-disclosure: another product's release and a release that does not
// exist are the same refusal, word for word. An unconfined caller keeps today's
// `404 unknown_release` and reads no ownership at all.
func TestResolve_ReleaseIDPathAuthorizesTheOwningProduct(t *testing.T) {
	reg := estate()
	reg.owners["rel-other"] = "prod-other"
	reg.releases["rel-other"] = true

	t.Run("its own release is filed against", func(t *testing.T) {
		got, err := subjectref.NewResolver(reg).Resolve(context.Background(), app.ResolveRequest{
			ReleaseID: "rel-1", Authorize: scopedTo("prod-1"),
		})
		if err != nil || got.ReleaseID != "rel-1" {
			t.Fatalf("got %+v, %v", got, err)
		}
	})

	var details []string
	for _, tc := range []struct{ name, releaseID string }{
		{"another product's release", "rel-other"},
		{"a release that does not exist", "rel-nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := subjectref.NewResolver(reg).Resolve(context.Background(), app.ResolveRequest{
				ReleaseID: tc.releaseID, Authorize: scopedTo("prod-1"),
			})
			re, ok := domain.AsReject(err)
			if !ok || re.Reason != domain.ReasonUnauthorized {
				t.Fatalf("error = %v, want an unauthorized refusal", err)
			}
			if strings.Contains(re.Detail, tc.releaseID) {
				t.Errorf("detail %q names the release id, which tells the caller which case it was", re.Detail)
			}
			details = append(details, re.Detail)
		})
	}
	if len(details) == 2 && details[0] != details[1] {
		t.Errorf("the two refusals differ:\n%q\n%q", details[0], details[1])
	}

	t.Run("an ownership that could not be read is refused, not resolved", func(t *testing.T) {
		broken := estate()
		broken.err, broken.failOn = errors.New("connection refused"), "owner"
		_, err := subjectref.NewResolver(broken).Resolve(context.Background(), app.ResolveRequest{
			ReleaseID: "rel-1", Authorize: scopedTo("prod-1"),
		})
		if re, ok := domain.AsReject(err); !ok || re.Reason != domain.ReasonUnauthorized {
			t.Fatalf("error = %v, want a fail-closed unauthorized refusal", err)
		}
	})

	t.Run("an unconfined caller keeps the unchanged 404 and reads no ownership", func(t *testing.T) {
		noOwners := estate()
		noOwners.owners = map[string]string{} // nothing to read; an admin must not need it
		if got, err := subjectref.NewResolver(noOwners).Resolve(context.Background(), byID("rel-1")); err != nil || got.ReleaseID != "rel-1" {
			t.Fatalf("own release = %+v, %v", got, err)
		}
		_, err := subjectref.NewResolver(noOwners).Resolve(context.Background(), byID("rel-nope"))
		if re, ok := domain.AsReject(err); !ok || re.Reason != domain.ReasonUnknownRelease {
			t.Fatalf("error = %v, want the unchanged unknown_release", err)
		}
	})
}

// TestStub_ProductOfReleaseKnowsNoProducts — the stub holds release ids, not the
// estate graph above them, so it answers with an empty id. The consequence is
// fail-closed and deliberate: on a stub-wired node a `product:<id>` key is refused
// even for a release in the allow-set, because nothing can establish who owns it.
func TestStub_ProductOfReleaseKnowsNoProducts(t *testing.T) {
	stub := subjectref.NewStub("rel-dev")
	if id, err := stub.ProductOfRelease(context.Background(), "rel-dev"); id != "" || err != nil {
		t.Errorf("ProductOfRelease = %q, %v; want an empty id and no error", id, err)
	}

	_, err := subjectref.NewResolver(stub).Resolve(context.Background(), app.ResolveRequest{
		ReleaseID: "rel-dev", Authorize: scopedTo("prod-1"),
	})
	if re, ok := domain.AsReject(err); !ok || re.Reason != domain.ReasonUnauthorized {
		t.Fatalf("error = %v, want a fail-closed unauthorized refusal", err)
	}
	// An admin (no authorizer) is unaffected: it never asks the question.
	if got, err := subjectref.NewResolver(stub).Resolve(context.Background(), byID("rel-dev")); err != nil || got.ReleaseID != "rel-dev" {
		t.Errorf("admin by id = %+v, %v", got, err)
	}
}
