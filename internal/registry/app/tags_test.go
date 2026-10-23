package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// estateFixture registers Product → Project → Release and records the project object the
// upward hop reads.
func estateFixture(t *testing.T) (*fakeRepo, *app.RegistryService, string, string, string) {
	t.Helper()
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newService(repo)
	prod, _, err := svc.RegisterProduct(ctx, "Gateway")
	if err != nil {
		t.Fatal(err)
	}
	proj, _, err := svc.RegisterProject(ctx, prod, "api")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := domain.NewProject(proj, prod, "api")
	if repo.projectObjs == nil {
		repo.projectObjs = map[string]domain.Project{}
	}
	repo.projectObjs[string(proj)] = p
	rel, _, err := svc.RegisterRelease(ctx, proj, "1.0")
	if err != nil {
		t.Fatal(err)
	}
	return repo, svc, string(prod), string(proj), string(rel)
}

func TestTags_SetAndEffective(t *testing.T) {
	ctx := context.Background()
	repo, svc, prod, proj, rel := estateFixture(t)
	if got, err := svc.SetTags(ctx, domain.TagProduct, prod, []string{"Team:Payments"}); err != nil || fmt.Sprint(got) != "[team:payments]" {
		t.Fatalf("product = %v %v", got, err)
	}
	if _, err := svc.SetTags(ctx, domain.TagProject, proj, []string{"env:prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetTags(ctx, domain.TagRelease, rel, []string{"customer-facing", "env:prod"}); err != nil {
		t.Fatal(err)
	}
	ts, err := svc.Tags(ctx, domain.TagRelease, rel)
	if err != nil || fmt.Sprint(ts.Own) != "[customer-facing env:prod]" || fmt.Sprint(ts.Effective) != "[customer-facing env:prod team:payments]" {
		t.Fatalf("release tags = %+v %v", ts, err)
	}
	pj, _ := svc.Tags(ctx, domain.TagProject, proj)
	if fmt.Sprint(pj.Effective) != "[env:prod team:payments]" {
		t.Fatalf("project tags = %+v", pj)
	}
	own, err := svc.OwnTags(ctx, domain.TagProduct, []string{prod, "other"})
	if err != nil || len(own) != 1 {
		t.Fatalf("own = %v %v", own, err)
	}
	_ = repo
}

func TestTags_Refusals(t *testing.T) {
	ctx := context.Background()
	repo, svc, prod, proj, rel := estateFixture(t)
	if _, err := svc.SetTags(ctx, domain.TagProduct, prod, []string{"bad tag"}); !errors.Is(err, domain.ErrInvalidTag) {
		t.Fatalf("bad tag = %v", err)
	}
	for kind, want := range map[domain.TagEntity]error{domain.TagProduct: app.ErrUnknownProduct, domain.TagProject: app.ErrUnknownProject, domain.TagRelease: app.ErrUnknownRelease} {
		if _, err := svc.SetTags(ctx, kind, "nope", nil); !errors.Is(err, want) {
			t.Errorf("%s unknown = %v", kind, err)
		}
		if _, err := svc.Tags(ctx, kind, "nope"); !errors.Is(err, want) {
			t.Errorf("%s unknown read = %v", kind, err)
		}
	}
	if _, err := svc.SetTags(ctx, "customer", "x", nil); !errors.Is(err, domain.ErrInvalidTag) {
		t.Fatalf("bad kind = %v", err)
	}
	repo.errProductExists = errors.New("db")
	if _, err := svc.SetTags(ctx, domain.TagProduct, prod, nil); err == nil {
		t.Fatal("exists error swallowed")
	}
	repo.errProductExists = nil
	repo.errTags = errors.New("db")
	if _, err := svc.SetTags(ctx, domain.TagProduct, prod, nil); err == nil {
		t.Fatal("store error swallowed")
	}
	if _, err := svc.Tags(ctx, domain.TagProduct, prod); err == nil {
		t.Fatal("read error swallowed")
	}
	repo.errTags = nil
	// Upward hops failing.
	delete(repo.projectObjs, proj)
	if _, err := svc.Tags(ctx, domain.TagProject, proj); err == nil {
		t.Fatal("project hop error swallowed")
	}
	if _, err := svc.Tags(ctx, domain.TagRelease, rel); err == nil {
		t.Fatal("release → project hop error swallowed")
	}
	repo.errGetRelease = errors.New("db")
	if _, err := svc.Tags(ctx, domain.TagRelease, rel); err == nil {
		t.Fatal("release read error swallowed")
	}
	repo.errGetRelease = nil
	p, _ := domain.NewProject(domain.ProjectID(proj), domain.ProductID(prod), "api")
	repo.projectObjs[proj] = p
	repo.tags = map[string][]string{}
	repo.errTags = nil
	failOnProduct := &tagFailRepo{fakeRepo: repo, failKind: domain.TagProduct}
	if _, err := newService(failOnProduct).Tags(ctx, domain.TagProject, proj); err == nil {
		t.Fatal("parent tags error swallowed")
	}
}

// tagFailRepo fails TagsOf for one kind only, to reach the parent-read error.
type tagFailRepo struct {
	*fakeRepo
	failKind domain.TagEntity
}

func (r *tagFailRepo) TagsOf(ctx context.Context, kind domain.TagEntity, ids []string) (map[string][]string, error) {
	if kind == r.failKind {
		return nil, errors.New("db")
	}
	return r.fakeRepo.TagsOf(ctx, kind, ids)
}
