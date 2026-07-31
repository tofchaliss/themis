package domain

import (
	"errors"
	"strings"
)

// DeploymentID is a Deployment's opaque, stable identity.
type DeploymentID string

// Deployment places a Microservice into an environment for a Customer — the edge that makes
// a Customer reachable from a Product for blast-radius (EDR-ESTATE-01 D2).
type Deployment struct {
	id           DeploymentID
	microservice MicroserviceID
	customer     CustomerID
	environment  string
}

// NewDeployment validates and constructs a Deployment. It must reference a Microservice and a
// Customer and name an environment.
func NewDeployment(id DeploymentID, microservice MicroserviceID, customer CustomerID, environment string) (Deployment, error) {
	environment = strings.TrimSpace(environment)
	switch {
	case id == "":
		return Deployment{}, errors.New("deployment: empty id")
	case microservice == "":
		return Deployment{}, errors.New("deployment: empty microservice id")
	case customer == "":
		return Deployment{}, errors.New("deployment: empty customer id")
	case environment == "":
		return Deployment{}, errors.New("deployment: empty environment")
	}
	return Deployment{id: id, microservice: microservice, customer: customer, environment: environment}, nil
}

// ID returns the stable deployment identity.
func (d Deployment) ID() DeploymentID { return d.id }

// MicroserviceID returns the deployed microservice's identity.
func (d Deployment) MicroserviceID() MicroserviceID { return d.microservice }

// CustomerID returns the served customer's identity.
func (d Deployment) CustomerID() CustomerID { return d.customer }

// Environment returns the deployment environment (e.g. "prod").
func (d Deployment) Environment() string { return d.environment }
