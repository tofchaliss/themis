package subjectref

import (
	"context"
	"fmt"

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
type Registry interface {
	ReleaseExists(ctx context.Context, releaseID string) (bool, error)
	ProductIDByName(ctx context.Context, name string) (string, error)
	ProjectIDByName(ctx context.Context, productID, name string) (string, error)
	ReleaseIDByVersion(ctx context.Context, projectID, version string) (string, error)
}

// Resolver resolves the release an intake names, READ-ONLY (EDR-INTAKE-01 D7). It
// satisfies the app's ReleaseResolver port.
//
// Read-only is the decision, not an implementation detail: intake never creates
// Registry identity. A write from Evidence into Registry is neither an event nor a
// read, and no convenience justifies punching through that — a create-if-missing
// flag would let one typo in a product name silently fork the estate graph, which is
// the thing Registry exists to prevent.
type Resolver struct{ reg Registry }

// NewResolver builds a resolver over the registry read seam.
func NewResolver(reg Registry) *Resolver { return &Resolver{reg: reg} }

// Resolve returns the canonical release id for either road, and refuses with
// [domain.ReasonUnknownRelease] naming WHICH of the three was not found — because
// "unknown release" on a three-part name leaves the operator guessing which part
// they got wrong, and the guess is the expensive bit.
func (r *Resolver) Resolve(ctx context.Context, product, project, version, releaseID string) (string, error) {
	if releaseID != "" {
		ok, err := r.reg.ReleaseExists(ctx, releaseID)
		if err != nil {
			return "", fmt.Errorf("release lookup: %w", err)
		}
		if !ok {
			return "", domain.Reject(domain.ReasonUnknownRelease, fmt.Sprintf(
				"release %q is not registered; register Product -> Project -> Release first (intake resolves identity, it never creates it)", releaseID))
		}
		return releaseID, nil
	}

	if product == "" || project == "" || version == "" {
		return "", domain.Reject(domain.ReasonUnknownRelease, fmt.Sprintf(
			"name the release either by release_id or by the whole {product, project, version} triple; got product=%q, project=%q, version=%q", product, project, version))
	}

	productID, err := r.reg.ProductIDByName(ctx, product)
	if err != nil {
		return "", fmt.Errorf("product lookup: %w", err)
	}
	if productID == "" {
		return "", notFound("product", product)
	}
	projectID, err := r.reg.ProjectIDByName(ctx, productID, project)
	if err != nil {
		return "", fmt.Errorf("project lookup: %w", err)
	}
	if projectID == "" {
		return "", notFound("project", project)
	}
	resolved, err := r.reg.ReleaseIDByVersion(ctx, projectID, version)
	if err != nil {
		return "", fmt.Errorf("release lookup: %w", err)
	}
	if resolved == "" {
		return "", notFound("release version", version)
	}
	return resolved, nil
}

func notFound(what, name string) error {
	return domain.Reject(domain.ReasonUnknownRelease,
		fmt.Sprintf("no %s named %q is registered", what, name))
}
