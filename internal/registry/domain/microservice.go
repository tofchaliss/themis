package domain

import (
	"errors"
	"strings"
)

// MicroserviceID is a Microservice's opaque, stable identity.
type MicroserviceID string

// Microservice is a runnable unit that belongs to exactly one Product (EDR-ESTATE-01 D2) —
// the estate graph's bridge from a Product to where it runs (its Deployments).
type Microservice struct {
	id      MicroserviceID
	product ProductID
	name    string
}

// NewMicroservice validates and constructs a Microservice. Every Microservice must belong
// to a Product (non-empty product id).
func NewMicroservice(id MicroserviceID, product ProductID, name string) (Microservice, error) {
	name = strings.TrimSpace(name)
	switch {
	case id == "":
		return Microservice{}, errors.New("microservice: empty id")
	case product == "":
		return Microservice{}, errors.New("microservice: empty product id")
	case name == "":
		return Microservice{}, errors.New("microservice: empty name")
	}
	return Microservice{id: id, product: product, name: name}, nil
}

// ID returns the stable microservice identity.
func (m Microservice) ID() MicroserviceID { return m.id }

// ProductID returns the owning product's identity.
func (m Microservice) ProductID() ProductID { return m.product }

// Name returns the microservice name.
func (m Microservice) Name() string { return m.name }
