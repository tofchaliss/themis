package app

import (
	"context"
	"fmt"

	"github.com/themis-project/themis/internal/registry/domain"
)

// Tags (EDR-REMEDIATION-01 D7): filters only, never a weight.

// TagSet is an entity's own tags and its effective tags (own ∪ its parents').
type TagSet struct {
	Own       []string
	Effective []string
}

func (s *RegistryService) exists(ctx context.Context, kind domain.TagEntity, id string) error {
	var (
		check func(context.Context, string) (bool, error)
		not   error
	)
	switch kind {
	case domain.TagProduct:
		check, not = s.repo.ProductExists, ErrUnknownProduct
	case domain.TagProject:
		check, not = s.repo.ProjectExists, ErrUnknownProject
	case domain.TagRelease:
		check, not = s.repo.ReleaseExists, ErrUnknownRelease
	default:
		return fmt.Errorf("%w: unknown tag entity %q", domain.ErrInvalidTag, kind)
	}
	ok, err := check(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return not
	}
	return nil
}

// SetTags replaces an entity's own tags after normalizing them.
func (s *RegistryService) SetTags(ctx context.Context, kind domain.TagEntity, id string, tags []string) ([]string, error) {
	norm, err := domain.NormalizeTags(tags)
	if err != nil {
		return nil, err
	}
	if err := s.exists(ctx, kind, id); err != nil {
		return nil, err
	}
	if err := s.repo.SetTags(ctx, kind, id, norm); err != nil {
		return nil, err
	}
	return norm, nil
}

func (s *RegistryService) own(ctx context.Context, kind domain.TagEntity, id string) ([]string, error) {
	m, err := s.repo.TagsOf(ctx, kind, []string{id})
	if err != nil {
		return nil, err
	}
	return m[id], nil
}

// Tags returns an entity's own and effective tags: a Project adds its Product's, a Release its
// Project's and Product's.
func (s *RegistryService) Tags(ctx context.Context, kind domain.TagEntity, id string) (TagSet, error) {
	if err := s.exists(ctx, kind, id); err != nil {
		return TagSet{}, err
	}
	own, err := s.own(ctx, kind, id)
	if err != nil {
		return TagSet{}, err
	}
	parents := []string{}
	switch kind {
	case domain.TagRelease:
		rel, err := s.repo.GetRelease(ctx, domain.ReleaseID(id))
		if err != nil {
			return TagSet{}, err
		}
		up, err := s.Tags(ctx, domain.TagProject, string(rel.ProjectID()))
		if err != nil {
			return TagSet{}, err
		}
		parents = up.Effective
	case domain.TagProject:
		proj, err := s.repo.GetProject(ctx, domain.ProjectID(id))
		if err != nil {
			return TagSet{}, err
		}
		if parents, err = s.own(ctx, domain.TagProduct, string(proj.ProductID())); err != nil {
			return TagSet{}, err
		}
	}
	return TagSet{Own: domain.UnionTags(own), Effective: domain.UnionTags(own, parents)}, nil
}

// OwnTags reads the own tags of many entities of one kind (for list views).
func (s *RegistryService) OwnTags(ctx context.Context, kind domain.TagEntity, ids []string) (map[string][]string, error) {
	return s.repo.TagsOf(ctx, kind, ids)
}

// TaggedReleases lists every release whose effective tags carry tag — one query, for a filter
// that spans the estate (What's new).
func (s *RegistryService) TaggedReleases(ctx context.Context, tag string) ([]domain.Release, error) {
	norm, err := domain.NormalizeTags([]string{tag})
	if err != nil {
		return nil, err
	}
	return s.repo.TaggedReleases(ctx, norm[0])
}
