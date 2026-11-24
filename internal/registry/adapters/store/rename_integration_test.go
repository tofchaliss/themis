//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// A rename changes the name only (EDR-KERNEL-01 D5): the release still hangs off the same id,
// find-or-create answers the NEW name with the same id, and the old name is free again.
func TestRenameProject(t *testing.T) {
	ctx := context.Background()
	s := store.New(newPool(t))
	prodID, projID, relID := seed(t, s)

	if err := s.RenameProject(ctx, projID, "project-a"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := s.GetProject(ctx, projID)
	if err != nil || got.Name() != "project-a" || got.ProductID() != prodID {
		t.Fatalf("after rename = %+v, %v", got, err)
	}
	rel, err := s.GetRelease(ctx, relID)
	if err != nil || rel.ProjectID() != projID {
		t.Fatalf("release moved: %+v, %v", rel, err)
	}
	id, created, err := s.UpsertProject(ctx, string(prodID), "PROJECT-A")
	if err != nil || created || id != string(projID) {
		t.Fatalf("find-or-create by the new name = %q created=%v err=%v, want the same id", id, created, err)
	}
	if _, created, err := s.UpsertProject(ctx, string(prodID), "api"); err != nil || !created {
		t.Fatalf("the old name should be free: created=%v err=%v", created, err)
	}

	// A change of case only is the same row, not a clash with itself.
	if err := s.RenameProject(ctx, projID, "Project-A"); err != nil {
		t.Fatalf("case-only rename: %v", err)
	}
}

// A name another project of the same product carries is refused and nothing changes; the
// same name under ANOTHER product is fine.
func TestRenameProjectClash(t *testing.T) {
	ctx := context.Background()
	s := store.New(newPool(t))
	prodID, projID, _ := seed(t, s)
	other, _ := domain.NewProject("proj-2", prodID, "project-b")
	if err := s.SaveProject(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameProject(ctx, projID, "PROJECT-B"); !errors.Is(err, app.ErrProjectNameTaken) {
		t.Fatalf("clash = %v, want ErrProjectNameTaken", err)
	}
	if got, _ := s.GetProject(ctx, projID); got.Name() != "api" {
		t.Errorf("a refused rename changed the name to %q", got.Name())
	}

	prod2, _ := domain.NewProduct("prod-2", "Other")
	if err := s.SaveProduct(ctx, prod2); err != nil {
		t.Fatal(err)
	}
	p3, _ := domain.NewProject("proj-3", "prod-2", "x")
	if err := s.SaveProject(ctx, p3); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameProject(ctx, "proj-3", "project-b"); err != nil {
		t.Fatalf("same name under another product: %v", err)
	}
}

func TestRenameProjectNotFound(t *testing.T) {
	s := store.New(newPool(t))
	if err := s.RenameProject(context.Background(), "nope", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}
