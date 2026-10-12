package subjectref

import (
	"context"
	"errors"
	"fmt"

	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
)

// Registry is the read seam release resolution needs onto the Shared Kernel
// registry. Every value crossing it is a primitive: no registry type reaches this
// context, which is what keeps a read seam from becoming a cross-context import.
//
// A name lookup that finds nothing returns an EMPTY id and a nil error — "not
// found" is an answer, not a fault, and the two must stay distinguishable. A non-nil
// error here means the lookup could not be PERFORMED, which is a statement about
// Themis, so the resolver passes it through unnamed rather than reporting the
// release unknown.
//
// The one exception is [ErrAmbiguousName]: a name lookup that matched more than one
// row ABSTAINS, and must say so (EDR-INTAKE-01 B4). That is a third answer, not a
// fault and not a miss — the thing is registered, twice — and an implementation of
// this seam returns this context's sentinel for it, never the registry's.
type Registry interface {
	ReleaseExists(ctx context.Context, releaseID string) (bool, error)
	ProductIDByName(ctx context.Context, name string) (string, error)
	ProjectIDByName(ctx context.Context, productID, name string) (string, error)
	ReleaseIDByVersion(ctx context.Context, projectID, version string) (string, error)
	// ProductOfRelease names the Product that OWNS a release — the upward hop
	// release -> project -> product that the `release_id` road needs in order to
	// authorize a product-scoped key before anything is written (EDR-INTAKE-01 B7).
	//
	// It is a READ, so the seam still carries no write. An unknown release is an
	// EMPTY id and a nil error (the seam's contract above); [ErrAmbiguousName] does
	// not apply — a release id is unique by construction, so there is no second row
	// to abstain between.
	ProductOfRelease(ctx context.Context, releaseID string) (string, error)
}

// Resolver resolves the release an intake names, READ-ONLY (EDR-INTAKE-01 D7). It
// satisfies the app's ReleaseResolver port.
//
// Read-only is the decision, not an implementation detail: resolution creates nothing,
// which is what keeps every border refusal free of a side effect. The one create intake
// can make is a VERSION, it goes through [Provisioner] after every border check, and
// what resolution contributes to it is an answer — "this version does not exist yet,
// under this project" ([app.Resolution.ToCreate]).
//
// A Product or Project that does not resolve is still a refusal and never a creation:
// those names are human-owned, and a typo in one is where a parallel estate comes from,
// which is the hazard D7 refused `create_if_missing` over (B2 narrows the wall to the
// version and says so explicitly).
type Resolver struct{ reg Registry }

// NewResolver builds a resolver over the registry read seam.
func NewResolver(reg Registry) *Resolver { return &Resolver{reg: reg} }

// unauthorizedDetail is what EVERY authorization refusal on this seam says, on both
// roads and in every one of the outcomes B3 requires a product-scoped key not to
// distinguish. It is ONE constant because that is what makes the refusals identical:
// three refusals written in three places are three strings that drift, and the first
// one to name the estate ("no product named X") turns intake into a product-name
// oracle for any holder of any product key.
//
// It states the RULE and never the estate — not which product owns the release, not
// whether the name resolved, not whether Registry answered. That is the same posture
// Governance's write gate took (EDR-DELIVERY-01 N-M0): a 403 body is the one surface
// an unauthorized caller is guaranteed to read, so it answers none of the questions
// they were refused permission to ask.
const unauthorizedDetail = "this key is not authorized for the product this request names; " +
	"a product-scoped key may file evidence only for its own product"

// unauthorized is B3's non-disclosing refusal.
func unauthorized() error { return domain.Reject(domain.ReasonUnauthorized, unauthorizedDetail) }

// Resolve returns the canonical release id for either road, and refuses with
// [domain.ReasonUnknownRelease] naming WHICH of the three was not found — because
// "unknown release" on a three-part name leaves the operator guessing which part
// they got wrong, and the guess is the expensive bit.
//
// It is also where B7's step 4 authorizes the caller against the RESOLVED product,
// on both roads, read-only, before anything is written. The order is the decision
// (B3): the product is authorized BEFORE the project is looked up, because asking
// about a project under a product the key may not see would leak that project's
// existence by the same oracle the `403` closes.
//
// `req.CreateRelease` changes exactly one of the answers: an ABSENT version under a
// Product and Project that resolved (and that the caller is authorized for) comes back
// as "to be created", naming the project, instead of `unknown_release`. Resolution
// still writes nothing — the find-or-create sits after every border check (B7's step 8,
// design §3 "why the create is late"), and every other answer here is unchanged.
func (r *Resolver) Resolve(ctx context.Context, req app.ResolveRequest) (app.Resolution, error) {
	if req.ReleaseID != "" {
		return r.resolveByID(ctx, req)
	}

	if req.Product == "" || req.Project == "" || req.Version == "" {
		return app.Resolution{}, domain.Reject(domain.ReasonUnknownRelease, fmt.Sprintf(
			"name the release either by release_id or by the whole {product, project, version} triple; got product=%q, project=%q, version=%q", req.Product, req.Project, req.Version))
	}

	productID, err := r.reg.ProductIDByName(ctx, req.Product)
	// B3's three indistinguishable outcomes, collapsed in ONE branch and placed
	// BEFORE the project lookup: resolves elsewhere, resolves nowhere, ambiguous.
	// A lookup that could not be PERFORMED joins them for a confined caller, because
	// an unverifiable confinement is not a confinement (the fail-closed rule
	// Governance's gate already runs on) — while an admin still gets the honest
	// infrastructure fault below.
	if req.Confined() && (err != nil || productID == "" || !req.Authorize(productID)) {
		return app.Resolution{}, unauthorized()
	}
	if err != nil {
		return app.Resolution{}, lookupFailed("product", req.Product, err)
	}
	if productID == "" {
		return app.Resolution{}, notFound("product", req.Product)
	}
	projectID, err := r.reg.ProjectIDByName(ctx, productID, req.Project)
	if err != nil {
		return app.Resolution{}, lookupFailed("project", req.Project, err)
	}
	if projectID == "" {
		return app.Resolution{}, notFound("project", req.Project)
	}
	resolved, err := r.reg.ReleaseIDByVersion(ctx, projectID, req.Version)
	if err != nil {
		return app.Resolution{}, lookupFailed("release version", req.Version, err)
	}
	if resolved == "" {
		// The only place `create_release` is consulted. The product and the project
		// are established and authorized at this point, so the absent version is the
		// one thing B2 lets intake create — reported as an answer, with the project it
		// goes under, and created later or not at all.
		if req.CreateRelease {
			return app.Resolution{ProjectID: projectID, Version: req.Version}, nil
		}
		return app.Resolution{}, notFound("release version", req.Version)
	}
	return app.Resolution{ReleaseID: resolved}, nil
}

// resolveByID is the direct road, and the ownership check comes BEFORE the existence
// answer on purpose (B7 rows 17-18): for a product-scoped key, another product's
// release and a release that does not exist are the SAME refusal. Telling the two
// apart would make a release id guessable by status code, which is the non-disclosure
// rule of B3 applied to ids exactly as to names.
//
// An unconfined caller (`admin`, or an auth-disabled node) reads no ownership at all
// and keeps today's answer unchanged: `404 unknown_release`.
// `create_release` cannot reach this road: naming the release both ways is refused on
// the parameters, before anything is read (B2's row 5), so there is nothing to create
// here and an unknown id stays `unknown_release` for an admin.
func (r *Resolver) resolveByID(ctx context.Context, req app.ResolveRequest) (app.Resolution, error) {
	if req.Confined() {
		productID, err := r.reg.ProductOfRelease(ctx, req.ReleaseID)
		// An empty id is refused on its own account rather than left to the
		// authorizer: "no such release" must reach the SAME refusal as "someone
		// else's release", and a check that depends on a key never matching the empty
		// product is a check resting on a coincidence.
		if err != nil || productID == "" || !req.Authorize(productID) {
			return app.Resolution{}, unauthorized()
		}
	}
	ok, err := r.reg.ReleaseExists(ctx, req.ReleaseID)
	if err != nil {
		return app.Resolution{}, fmt.Errorf("release lookup: %w", err)
	}
	if !ok {
		return app.Resolution{}, domain.Reject(domain.ReasonUnknownRelease, fmt.Sprintf(
			"release %q is not registered; register Product -> Project -> Release first (intake resolves identity, it never creates it)", req.ReleaseID))
	}
	return app.Resolution{ReleaseID: req.ReleaseID}, nil
}

func notFound(what, name string) error {
	return domain.Reject(domain.ReasonUnknownRelease,
		fmt.Sprintf("no %s named %q is registered", what, name))
}

// lookupFailed splits the two things a non-nil lookup error can mean. An abstention
// ([ErrAmbiguousName]) is a REFUSAL the caller can act on, and it must be worded as
// ambiguity: "no product named X is registered" is a false statement about a product
// that is registered twice, and it sends the operator hunting for a typo that is not
// there. Anything else is a seam that could not be READ, which says nothing about
// whether the release exists, so it passes through carrying no reason at all.
func lookupFailed(what, name string, err error) error {
	if errors.Is(err, ErrAmbiguousName) {
		return domain.Reject(domain.ReasonAmbiguousName, fmt.Sprintf(
			"%s %q is ambiguous: it matches more than one row in the registry, and intake will "+
				"not guess which one you mean — name the release by release_id, or de-duplicate the registry",
			what, name))
	}
	return fmt.Errorf("%s lookup: %w", what, err)
}
