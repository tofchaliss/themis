//go:build integration

package assetgraph_test

import (
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/adapter/assetgraph"
)

func TestSentinelErrors(t *testing.T) {
	cases := []error{
		assetgraph.ErrProductNotFound,
		assetgraph.ErrMicroserviceNotFound,
		assetgraph.ErrCustomerNotFound,
		assetgraph.ErrDuplicateMicroservice,
		assetgraph.ErrDuplicateCustomer,
		assetgraph.ErrDuplicateDeployment,
	}
	for _, err := range cases {
		if err == nil || err.Error() == "" {
			t.Fatalf("empty sentinel: %v", err)
		}
		if !errors.Is(err, err) {
			t.Fatalf("errors.Is failed for %v", err)
		}
	}
}
