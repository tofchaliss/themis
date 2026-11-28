package domain

import (
	"errors"
	"strings"
)

// ErrEmptyProjectName is a project name that is empty once trimmed.
var ErrEmptyProjectName = errors.New("project: empty name")

// ProjectID is a Project's opaque, stable identity.
type ProjectID string

// Project is a deliverable that belongs to exactly one Product (Book II §4.2).
// Structural identity + membership only. The id and the product are immutable; the name is a
// label and may be corrected with Rename (EDR-KERNEL-01 D5), because every other context
// refers to a project by id.
type Project struct {
	id      ProjectID
	product ProductID
	name    string
}

// NewProject validates and constructs a Project. Every Project must belong to a
// Product (non-empty product id).
func NewProject(id ProjectID, product ProductID, name string) (Project, error) {
	name = strings.TrimSpace(name)
	switch {
	case id == "":
		return Project{}, errors.New("project: empty id")
	case product == "":
		return Project{}, errors.New("project: empty product id")
	case name == "":
		return Project{}, ErrEmptyProjectName
	}
	return Project{id: id, product: product, name: name}, nil
}

// ID returns the stable project identity.
func (p Project) ID() ProjectID { return p.id }

// ProductID returns the owning product's identity.
func (p Project) ProductID() ProductID { return p.product }

// Name returns the project name.
func (p Project) Name() string { return p.name }

// Rename returns the project with a new name, validated like NewProject's (trimmed, non-empty).
// The id and the owning product never change: a rename moves nothing.
func (p Project) Rename(name string) (Project, error) {
	return NewProject(p.id, p.product, name)
}
