package domain

import (
	"errors"
	"strings"
)

// CustomerID is a Customer's opaque, stable identity.
type CustomerID string

// Customer is the enterprise impact unit — an organization a Deployment serves. It is
// the leaf the blast-radius traversal counts (EDR-ESTATE-01 D2). Identity only.
type Customer struct {
	id   CustomerID
	name string
}

// NewCustomer validates and constructs a Customer.
func NewCustomer(id CustomerID, name string) (Customer, error) {
	name = strings.TrimSpace(name)
	switch {
	case id == "":
		return Customer{}, errors.New("customer: empty id")
	case name == "":
		return Customer{}, errors.New("customer: empty name")
	}
	return Customer{id: id, name: name}, nil
}

// ID returns the stable customer identity.
func (c Customer) ID() CustomerID { return c.id }

// Name returns the customer name.
func (c Customer) Name() string { return c.name }
