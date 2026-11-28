package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

func renameRepo(t *testing.T) *fakeRepo {
	t.Helper()
	repo := newFakeRepo()
	p, err := domain.NewProject("proj-1", "prod-1", "wrong-name")
	if err != nil {
		t.Fatal(err)
	}
	repo.projects["proj-1"] = true
	repo.projectObjs = map[string]domain.Project{"proj-1": p}
	return repo
}

// A rename keeps the id and the product, trims the name, and reports the old one.
func TestRenameProject(t *testing.T) {
	repo := renameRepo(t)
	got, old, err := newService(repo).RenameProject(context.Background(), "proj-1", "  project-a ")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got.ID() != "proj-1" || got.ProductID() != "prod-1" || got.Name() != "project-a" || old != "wrong-name" {
		t.Errorf("got %+v old %q", got, old)
	}
	if repo.projectObjs["proj-1"].Name() != "project-a" || repo.renames != 1 {
		t.Errorf("store not written: %+v renames=%d", repo.projectObjs["proj-1"], repo.renames)
	}
}

// The same name again writes nothing: a retried request is harmless.
func TestRenameProjectSameNameWritesNothing(t *testing.T) {
	repo := renameRepo(t)
	got, old, err := newService(repo).RenameProject(context.Background(), "proj-1", "wrong-name")
	if err != nil || got.Name() != "wrong-name" || old != "wrong-name" || repo.renames != 0 {
		t.Errorf("got %+v old %q err %v renames %d", got, old, err, repo.renames)
	}
}

func TestRenameProjectRefusals(t *testing.T) {
	boom := errors.New("boom")
	for name, tc := range map[string]struct {
		id     domain.ProjectID
		newNm  string
		setup  func(*fakeRepo)
		wantIs error
	}{
		"unknown project": {id: "nope", newNm: "x", wantIs: app.ErrUnknownProject},
		"empty name":      {id: "proj-1", newNm: "  "},
		"name taken":      {id: "proj-1", newNm: "project-b", setup: func(r *fakeRepo) { r.errRename = app.ErrProjectNameTaken }, wantIs: app.ErrProjectNameTaken},
		"exists error":    {id: "proj-1", newNm: "x", setup: func(r *fakeRepo) { r.errProjectExists = boom }, wantIs: boom},
		"store error":     {id: "proj-1", newNm: "x", setup: func(r *fakeRepo) { r.errRename = boom }, wantIs: boom},
		"get error":       {id: "proj-1", newNm: "x", setup: func(r *fakeRepo) { delete(r.projectObjs, "proj-1") }},
	} {
		t.Run(name, func(t *testing.T) {
			repo := renameRepo(t)
			if tc.setup != nil {
				tc.setup(repo)
			}
			_, _, err := newService(repo).RenameProject(context.Background(), tc.id, tc.newNm)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("err = %v, want %v", err, tc.wantIs)
			}
		})
	}
}
