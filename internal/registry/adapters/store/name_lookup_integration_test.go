//go:build integration

// Exact-name lookups abstain, and say *ambiguous* (EDR-INTAKE-01 amendment B4, task 1.9).
//
// The ambiguity tests seed the schema at version 2 — WITHOUT 000003's unique indexes — because
// that is the only estate shape in which `>1` is reachable at all. The guard exists for exactly
// that shape: an un-migrated estate still has the old tables, and a guard that only holds
// because of an index is a guard that disappears with the index.
//
// The harness (TestMain, newPool, truncate, mustExec) lives in store_integration_test.go and
// the version juggling (withoutUniquenessIndexes) in uniqueness_migration_integration_test.go,
// so these tests move the same schema through the same migrator the node uses.

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/app"
)

// TestProductIDByNameAbstainsOnMoreThanOneMatch — "OAMP" and "oamp" are one product name under
// B4's case folding, so a registry holding both cannot answer which one an intake meant.
// Returning either would be inventing the operator's intent; returning "not found" would be a
// false statement about a product that is registered twice.
func TestProductIDByNameAbstainsOnMoreThanOneMatch(t *testing.T) {
	pool := newPool(t)
	withoutUniquenessIndexes(t, pool)
	s := store.New(pool)

	mustExec(t, pool, insertProductSQL, "prod-oamp-upper", "OAMP")
	mustExec(t, pool, insertProductSQL, "prod-oamp-lower", "oamp")

	id, err := s.ProductIDByName(context.Background(), "OAMP")
	if !errors.Is(err, app.ErrAmbiguousName) {
		t.Fatalf("err = %v, want ErrAmbiguousName", err)
	}
	if id != "" {
		t.Errorf("id = %q, want nothing: an abstention that still answers is not an abstention", id)
	}
}

// TestProjectIDByNameAbstainsWithinItsProduct — the same guard one level down. The duplicate has
// to be under the SAME product to be ambiguous: the same project name under a different product
// is a different row, which is the uniqueness key and not a filter on the answer.
func TestProjectIDByNameAbstainsWithinItsProduct(t *testing.T) {
	pool := newPool(t)
	withoutUniquenessIndexes(t, pool)
	s := store.New(pool)
	ctx := context.Background()

	mustExec(t, pool, insertProductSQL, "prod-1", "OAMP")
	mustExec(t, pool, insertProductSQL, "prod-2", "Other")
	mustExec(t, pool, insertProjectSQL, "proj-1", "prod-1", "oamp-core")
	mustExec(t, pool, insertProjectSQL, "proj-2", "prod-1", "OAMP-Core")
	mustExec(t, pool, insertProjectSQL, "proj-3", "prod-2", "oamp-core")

	if id, err := s.ProjectIDByName(ctx, "prod-1", "oamp-core"); !errors.Is(err, app.ErrAmbiguousName) || id != "" {
		t.Errorf("duplicated under its product = %q, %v; want an abstention", id, err)
	}
	if id, err := s.ProjectIDByName(ctx, "prod-2", "oamp-core"); err != nil || id != "proj-3" {
		t.Errorf("the other product's project = %q, %v; want proj-3 — the name is scoped, not shared", id, err)
	}
}

// TestReleaseIDByVersionAbstainsInsteadOfPickingTheFirst is the behaviour change B4 names
// outright: this lookup used to scan a project's releases and return the first exact hit, which
// silently chose a winner the moment two existed. It now abstains.
func TestReleaseIDByVersionAbstainsInsteadOfPickingTheFirst(t *testing.T) {
	pool := newPool(t)
	withoutUniquenessIndexes(t, pool)
	s := store.New(pool)

	mustExec(t, pool, insertProductSQL, "prod-1", "OAMP")
	mustExec(t, pool, insertProjectSQL, "proj-1", "prod-1", "oamp-core")
	mustExec(t, pool, insertReleaseSQL, "rel-first", "proj-1", "R1917.256")
	mustExec(t, pool, insertReleaseSQL, "rel-second", "proj-1", "R1917.256")

	id, err := s.ReleaseIDByVersion(context.Background(), "proj-1", "R1917.256")
	if !errors.Is(err, app.ErrAmbiguousName) {
		t.Fatalf("err = %v, want ErrAmbiguousName", err)
	}
	if id != "" {
		t.Errorf("id = %q, want nothing — picking one of two builds is inventing the caller's intent", id)
	}
}

// TestNameLookupMissIsNotAnError — zero matches stays an empty id and a nil error at every
// level. "Not found" is an answer the resolver turns into a refusal naming the part that missed;
// an error would mean the lookup could not be PERFORMED, and the two must not collapse into one.
func TestNameLookupMissIsNotAnError(t *testing.T) {
	pool := newPool(t)
	s := store.New(pool)
	ctx := context.Background()

	_, projID, _ := seed(t, s)

	for _, c := range []struct {
		name string
		call func() (string, error)
	}{
		{"product", func() (string, error) { return s.ProductIDByName(ctx, "no-such-product") }},
		{"project under a real product", func() (string, error) {
			return s.ProjectIDByName(ctx, "prod-1", "no-such-project")
		}},
		{"project under an unknown product", func() (string, error) {
			return s.ProjectIDByName(ctx, "no-such-product-id", "api")
		}},
		{"release version", func() (string, error) { return s.ReleaseIDByVersion(ctx, string(projID), "9.9.9") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, err := c.call()
			if id != "" || err != nil {
				t.Errorf("= %q, %v; want an empty id and no error", id, err)
			}
		})
	}
}

// TestNameLookupMatchesNamesCaseInsensitivelyAndVersionsExactly pins the asymmetry to the
// indexes the lookups have to agree with: a Product/Project name is a human-typed label, so it
// folds case; a version is a machine build string whose case Themis does not own, so it is exact
// and never a prefix. A lookup that matched differently from the upsert would miss the row the
// upsert returned.
func TestNameLookupMatchesNamesCaseInsensitivelyAndVersionsExactly(t *testing.T) {
	pool := newPool(t)
	s := store.New(pool)
	ctx := context.Background()

	mustExec(t, pool, insertProductSQL, "prod-1", "OAMP")
	mustExec(t, pool, insertProjectSQL, "proj-1", "prod-1", "oamp-core")
	mustExec(t, pool, insertReleaseSQL, "rel-1", "proj-1", "R1917.256")

	for _, c := range []struct {
		name, want string
		call       func() (string, error)
	}{
		{"product, as stored", "prod-1", func() (string, error) { return s.ProductIDByName(ctx, "OAMP") }},
		{"product, other casing", "prod-1", func() (string, error) { return s.ProductIDByName(ctx, "oAmP") }},
		{"project, other casing", "proj-1", func() (string, error) { return s.ProjectIDByName(ctx, "prod-1", "OAMP-CORE") }},
		{"version, exact", "rel-1", func() (string, error) { return s.ReleaseIDByVersion(ctx, "proj-1", "R1917.256") }},
		{"version, other casing", "", func() (string, error) { return s.ReleaseIDByVersion(ctx, "proj-1", "r1917.256") }},
		{"version, a prefix of it", "", func() (string, error) { return s.ReleaseIDByVersion(ctx, "proj-1", "R1917.25") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, err := c.call()
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if id != c.want {
				t.Errorf("id = %q, want %q", id, c.want)
			}
		})
	}
}
