//go:build integration

package store_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/adapter/assetgraph"
	"github.com/themis-project/themis/internal/domain"
)

func TestAssetGraphRegistrationChain(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15456)
	graph := assetgraph.NewPostgresStore(pool)

	productID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ($1, 'payments')`, productID); err != nil {
		t.Fatal(err)
	}

	ms, err := graph.CreateMicroservice(ctx, domain.Microservice{
		ProductID: productID,
		Name:      "checkout-api",
		TechStack: map[string]string{"lang": "go"},
	})
	if err != nil {
		t.Fatalf("CreateMicroservice() error = %v", err)
	}

	customer, err := graph.CreateCustomer(ctx, domain.Customer{
		Name:         "platform-team",
		ContactEmail: "platform@example.com",
	})
	if err != nil {
		t.Fatalf("CreateCustomer() error = %v", err)
	}

	if _, err := graph.CreateDeployment(ctx, domain.Deployment{
		MicroserviceID: ms.ID,
		CustomerID:     customer.ID,
		Environment:    "production",
		Region:         "us-east-1",
	}); err != nil {
		t.Fatalf("CreateDeployment() error = %v", err)
	}

	var edgeCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM asset_graph_edges`).Scan(&edgeCount); err != nil {
		t.Fatal(err)
	}
	if edgeCount < 3 {
		t.Fatalf("edge count = %d, want >= 3", edgeCount)
	}

	if _, err := graph.CreateMicroservice(ctx, domain.Microservice{
		ProductID: productID,
		Name:      "checkout-api",
	}); err != assetgraph.ErrDuplicateMicroservice {
		t.Fatalf("duplicate microservice err = %v", err)
	}
}
