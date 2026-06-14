//go:build integration

package assetgraph

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/domain"
)

func TestComputeBlastRadiusMissingFields(t *testing.T) {
	store := NewPostgresStore(&mockPool{})
	result, err := store.ComputeBlastRadius(context.Background(), domain.EnrichmentFinding{})
	if err != nil || result.Score != domain.RiskScoreBlastRadiusMin {
		t.Fatalf("ComputeBlastRadius() = %+v, %v", result, err)
	}
}

func TestSbomActiveMissing(t *testing.T) {
	store := NewPostgresStore(&mockPool{row: mockRow{err: pgx.ErrNoRows}})
	active, err := store.sbomActive(context.Background(), "missing")
	if err != nil || active {
		t.Fatalf("sbomActive() = %v, %v", active, err)
	}
}

func TestCustomersFromProductQueryError(t *testing.T) {
	store := NewPostgresStore(&mockPool{queryErr: errors.New("query failed")})
	_, err := store.customersFromProduct(context.Background(), "prod-1")
	if err == nil {
		t.Fatal("expected query error")
	}
}

func TestProductBlastRadiusEmptyProduct(t *testing.T) {
	store := NewPostgresStore(&mockPool{})
	result, err := store.ProductBlastRadius(context.Background(), "", "", "")
	if err != nil || result.Score != 1.0 {
		t.Fatalf("ProductBlastRadius() = %+v, %v", result, err)
	}
}

func TestEnrichDelegatesToCompute(t *testing.T) {
	store := NewPostgresStore(&mockPool{})
	result, err := store.Enrich(context.Background(), domain.EnrichmentFinding{})
	if err != nil || result.Score != 1.0 {
		t.Fatalf("Enrich() = %+v, %v", result, err)
	}
}
