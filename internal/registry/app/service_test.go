package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// fakeRepo is an in-memory Repository with error-injection hooks for the failure paths.
type fakeRepo struct {
	products map[string]bool
	projects map[string]bool
	releases map[string]domain.Release

	errProductExists error
	errProjectExists error
	errReleaseExists error
	errSaveProduct   error
	errSaveProject   error
	errSaveRelease   error
	errGetRelease    error
	errList          error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{products: map[string]bool{}, projects: map[string]bool{}, releases: map[string]domain.Release{}}
}

func (r *fakeRepo) SaveProduct(_ context.Context, p domain.Product) error {
	if r.errSaveProduct != nil {
		return r.errSaveProduct
	}
	r.products[string(p.ID())] = true
	return nil
}

func (r *fakeRepo) SaveProject(_ context.Context, p domain.Project) error {
	if r.errSaveProject != nil {
		return r.errSaveProject
	}
	r.projects[string(p.ID())] = true
	return nil
}

func (r *fakeRepo) SaveRelease(_ context.Context, rel domain.Release) error {
	if r.errSaveRelease != nil {
		return r.errSaveRelease
	}
	r.releases[string(rel.ID())] = rel
	return nil
}

func (r *fakeRepo) GetRelease(_ context.Context, id domain.ReleaseID) (domain.Release, error) {
	if r.errGetRelease != nil {
		return domain.Release{}, r.errGetRelease
	}
	return r.releases[string(id)], nil
}

func (r *fakeRepo) ListReleases(_ context.Context, _ domain.ProjectID) ([]domain.Release, error) {
	if r.errList != nil {
		return nil, r.errList
	}
	out := make([]domain.Release, 0, len(r.releases))
	for _, rel := range r.releases {
		out = append(out, rel)
	}
	return out, nil
}

func (r *fakeRepo) ProductExists(_ context.Context, id string) (bool, error) {
	return r.products[id], r.errProductExists
}
func (r *fakeRepo) ProjectExists(_ context.Context, id string) (bool, error) {
	return r.projects[id], r.errProjectExists
}
func (r *fakeRepo) ReleaseExists(_ context.Context, id string) (bool, error) {
	_, ok := r.releases[id]
	return ok, r.errReleaseExists
}

// seqIDs yields deterministic ids for assertions.
type seqIDs struct{ n int }

func (s *seqIDs) NewID() string {
	s.n++
	return map[int]string{1: "id-1", 2: "id-2", 3: "id-3"}[s.n]
}

func newService(repo app.Repository) *app.RegistryService {
	return app.NewRegistryService(repo, &seqIDs{})
}

func TestRegisterProduct(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newService(repo)

	id, err := svc.RegisterProduct(ctx, "Themis")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id != "id-1" || !repo.products["id-1"] {
		t.Errorf("product not saved: id=%q", id)
	}

	// Invalid name → domain error, nothing saved.
	if _, err := newService(newFakeRepo()).RegisterProduct(ctx, "  "); err == nil {
		t.Error("empty name: expected error")
	}
	// Save failure surfaces.
	failing := newFakeRepo()
	failing.errSaveProduct = errors.New("boom")
	if _, err := newService(failing).RegisterProduct(ctx, "Themis"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestRegisterProject(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.products["prod-1"] = true
	svc := newService(repo)

	id, err := svc.RegisterProject(ctx, "prod-1", "api")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id != "id-1" {
		t.Errorf("project id = %q, want id-1", id)
	}

	// Unknown product.
	if _, err := newService(newFakeRepo()).RegisterProject(ctx, "nope", "api"); !errors.Is(err, app.ErrUnknownProduct) {
		t.Errorf("unknown product: err = %v, want ErrUnknownProduct", err)
	}
	// ProductExists error.
	pe := newFakeRepo()
	pe.errProductExists = errors.New("db down")
	if _, err := newService(pe).RegisterProject(ctx, "prod-1", "api"); err == nil {
		t.Error("ProductExists error: expected error")
	}
	// Invalid name (product exists).
	if _, err := svc.RegisterProject(ctx, "prod-1", " "); err == nil {
		t.Error("empty name: expected error")
	}
	// Save failure.
	sf := newFakeRepo()
	sf.products["prod-1"] = true
	sf.errSaveProject = errors.New("boom")
	if _, err := newService(sf).RegisterProject(ctx, "prod-1", "api"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestRegisterRelease(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.projects["proj-1"] = true
	svc := newService(repo)

	id, err := svc.RegisterRelease(ctx, "proj-1", "1.2.3")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id != "id-1" {
		t.Errorf("release id = %q, want id-1", id)
	}

	// Unknown project.
	if _, err := newService(newFakeRepo()).RegisterRelease(ctx, "nope", "1.0"); !errors.Is(err, app.ErrUnknownProject) {
		t.Errorf("unknown project: err = %v, want ErrUnknownProject", err)
	}
	// ProjectExists error.
	pe := newFakeRepo()
	pe.errProjectExists = errors.New("db down")
	if _, err := newService(pe).RegisterRelease(ctx, "proj-1", "1.0"); err == nil {
		t.Error("ProjectExists error: expected error")
	}
	// Invalid version.
	if _, err := svc.RegisterRelease(ctx, "proj-1", "  "); err == nil {
		t.Error("empty version: expected error")
	}
	// Save failure.
	sf := newFakeRepo()
	sf.projects["proj-1"] = true
	sf.errSaveRelease = errors.New("boom")
	if _, err := newService(sf).RegisterRelease(ctx, "proj-1", "1.0"); err == nil {
		t.Error("save error: expected error")
	}
}

func TestReadPaths(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	rel, _ := domain.NewRelease("rel-1", "proj-1", "1.0")
	repo.releases["rel-1"] = rel
	svc := newService(repo)

	if ok, err := svc.ReleaseExists(ctx, "rel-1"); err != nil || !ok {
		t.Errorf("ReleaseExists(rel-1) = %v,%v want true,nil", ok, err)
	}
	if ok, _ := svc.ReleaseExists(ctx, "missing"); ok {
		t.Error("ReleaseExists(missing) = true, want false")
	}
	got, err := svc.GetRelease(ctx, "rel-1")
	if err != nil || got.ID() != "rel-1" {
		t.Errorf("GetRelease = %+v, %v", got, err)
	}
	list, err := svc.ListReleases(ctx, "proj-1")
	if err != nil || len(list) != 1 {
		t.Errorf("ListReleases = %+v, %v", list, err)
	}
}
