//go:build integration

package store_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/domain"
)

// TestProductOfReleaseWalksUpToTheOwningProduct — the upward hop both Evidence doors
// authorize a product-scoped key against (EDR-INTAKE-01 B7). Two answers, and they
// are distinct on purpose: the owning product id, or an EMPTY id with a nil error for
// a release that does not exist. A caller that cannot tell those apart reports a
// database outage as a missing release — and on the authorization path it would then
// have to treat an unreadable seam and an unknown release alike for the wrong reason.
func TestProductOfReleaseWalksUpToTheOwningProduct(t *testing.T) {
	ctx := context.Background()
	s := store.New(newPool(t))
	prodID, _, relID := seed(t, s)

	got, err := s.ProductOfRelease(ctx, string(relID))
	if err != nil {
		t.Fatalf("ProductOfRelease: %v", err)
	}
	if got != string(prodID) {
		t.Errorf("owner of %s = %q, want %q", relID, got, prodID)
	}

	// A second product's release resolves to ITS product, so the hop is a traversal
	// and not one lucky row.
	other, err := domain.NewProduct("prod-2", "Other")
	must(t, err)
	must(t, s.SaveProduct(ctx, other))
	otherProj, err := domain.NewProject("proj-2", "prod-2", "api")
	must(t, err)
	must(t, s.SaveProject(ctx, otherProj))
	otherRel, err := domain.NewRelease("rel-2", "proj-2", "1.2.3")
	must(t, err)
	must(t, s.SaveRelease(ctx, otherRel))

	if got, err = s.ProductOfRelease(ctx, "rel-2"); err != nil || got != "prod-2" {
		t.Errorf("owner of rel-2 = %q, %v; want prod-2", got, err)
	}

	missing, err := s.ProductOfRelease(ctx, "rel-does-not-exist")
	if err != nil {
		t.Fatalf("an unknown release is an answer, not a fault: %v", err)
	}
	if missing != "" {
		t.Errorf("owner of an unknown release = %q, want an empty id", missing)
	}
}
