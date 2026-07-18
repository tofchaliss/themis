package domain

import (
	"errors"
	"strings"
)

// ProjectID is a Project's opaque, stable identity.
type ProjectID string

// Project is a deliverable that belongs to exactly one Product (Book II §4.2).
// Immutable structural identity + membership only.
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
		return Project{}, errors.New("project: empty name")
	}
	return Project{id: id, product: product, name: name}, nil
}

// ID returns the stable project identity.
func (p Project) ID() ProjectID { return p.id }

// ProductID returns the owning product's identity.
func (p Project) ProductID() ProductID { return p.product }

// Name returns the project name.
func (p Project) Name() string { return p.name }
