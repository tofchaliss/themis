package assetgraph

import "errors"

var (
	ErrProductNotFound       = errors.New("product not found")
	ErrMicroserviceNotFound  = errors.New("microservice not found")
	ErrCustomerNotFound      = errors.New("customer not found")
	ErrDuplicateMicroservice = errors.New("duplicate microservice")
	ErrDuplicateCustomer     = errors.New("duplicate customer")
	ErrDuplicateDeployment   = errors.New("duplicate deployment")
)
