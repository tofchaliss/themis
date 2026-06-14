package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/adapter/api"
	"github.com/themis-project/themis/internal/domain"
)

type fakeGraph struct {
	blast     domain.BlastRadiusResult
	blastErr  error
	customers map[string]domain.Customer
}

func (f *fakeGraph) CreateMicroservice(context.Context, domain.Microservice) (domain.Microservice, error) {
	return domain.Microservice{}, nil
}
func (f *fakeGraph) CreateDeployment(context.Context, domain.Deployment) (domain.Deployment, error) {
	return domain.Deployment{}, nil
}
func (f *fakeGraph) CreateCustomer(context.Context, domain.Customer) (domain.Customer, error) {
	return domain.Customer{}, nil
}
func (f *fakeGraph) GetMicroservice(context.Context, string) (domain.Microservice, error) {
	return domain.Microservice{}, nil
}
func (f *fakeGraph) GetCustomer(_ context.Context, id string) (domain.Customer, error) {
	if c, ok := f.customers[id]; ok {
		return c, nil
	}
	return domain.Customer{ID: id, Name: id}, nil
}
func (f *fakeGraph) ComputeBlastRadius(context.Context, domain.EnrichmentFinding) (domain.BlastRadiusResult, error) {
	return f.blast, f.blastErr
}
func (f *fakeGraph) ProductBlastRadius(context.Context, string, string, string) (domain.BlastRadiusResult, error) {
	return f.blast, f.blastErr
}

func TestGetProductBlastRadius(t *testing.T) {
	graph := &fakeGraph{
		blast: domain.BlastRadiusResult{Score: 1.4, CustomerIDs: []string{"cust-1", "cust-2"}},
		customers: map[string]domain.Customer{
			"cust-1": {ID: "cust-1", Name: "platform"},
			"cust-2": {ID: "cust-2", Name: "payments"},
		},
	}
	handler := api.NewHandler(api.Dependencies{Graph: graph})
	r := chi.NewRouter()
	r.Get("/api/v1/products/{id}/blast-radius", handler.GetProductBlastRadius)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/blast-radius", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		BlastRadiusScore    float64             `json:"blast_radius_score"`
		AffectedTeams       []map[string]string `json:"affected_teams"`
		UniqueCustomerCount int                 `json:"unique_customer_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.BlastRadiusScore != 1.4 || resp.UniqueCustomerCount != 2 || len(resp.AffectedTeams) != 2 {
		t.Fatalf("response = %+v", resp)
	}
}

func TestGetProductBlastRadiusUnavailable(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{})
	r := chi.NewRouter()
	r.Get("/api/v1/products/{id}/blast-radius", handler.GetProductBlastRadius)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/blast-radius", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
}
