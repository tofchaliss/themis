package domain

import (
	"errors"
	"strings"
)

// ProductID is a Product's opaque, stable identity.
type ProductID string

// Product is the top of the registry hierarchy: a named piece of software the
// enterprise owns. It is immutable structural identity only — no security state.
type Product struct {
	id   ProductID
	name string
}

// NewProduct validates and constructs a Product.
func NewProduct(id ProductID, name string) (Product, error) {
	name = strings.TrimSpace(name)
	switch {
	case id == "":
		return Product{}, errors.New("product: empty id")
	case name == "":
		return Product{}, errors.New("product: empty name")
	}
	return Product{id: id, name: name}, nil
}

// ID returns the stable product identity.
func (p Product) ID() ProductID { return p.id }

// Name returns the product name.
func (p Product) Name() string { return p.name }
