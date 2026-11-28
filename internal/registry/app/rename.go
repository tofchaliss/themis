package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/themis-project/themis/internal/registry/domain"
)

// ErrProjectNameTaken reports that another project of the same product already carries the
// name a rename asked for (case folded, like the find-or-create index). Nothing was changed.
var ErrProjectNameTaken = errors.New("registry: project name already taken in this product")

// RenameProject corrects a project's name (EDR-KERNEL-01 D5). Only the name changes: the id and
// the owning product stay, so everything another context keyed to the project — findings,
// decisions, watches, delivery intents — still points at it, and each reads the new name live.
// Unknown project → ErrUnknownProject; a name another project of the product carries →
// ErrProjectNameTaken. It returns the project as it now is and the name it had before.
func (s *RegistryService) RenameProject(ctx context.Context, id domain.ProjectID, name string) (domain.Project, string, error) {
	ok, err := s.repo.ProjectExists(ctx, string(id))
	if err != nil {
		return domain.Project{}, "", err
	}
	if !ok {
		return domain.Project{}, "", fmt.Errorf("%w: %q", ErrUnknownProject, id)
	}
	cur, err := s.repo.GetProject(ctx, id)
	if err != nil {
		return domain.Project{}, "", err
	}
	renamed, err := cur.Rename(name)
	if err != nil {
		return domain.Project{}, "", err
	}
	if renamed.Name() == cur.Name() {
		return cur, cur.Name(), nil // already this name: nothing to write
	}
	if err := s.repo.RenameProject(ctx, id, renamed.Name()); err != nil {
		return domain.Project{}, "", err
	}
	return renamed, cur.Name(), nil
}
