package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/domain"
)

// CreateMicroservice handles POST /api/v1/products/{id}/microservices.
func (h *Handler) CreateMicroservice(w http.ResponseWriter, r *http.Request) {
	if h.deps.Graph == nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "asset graph unavailable")
		return
	}
	productID := chi.URLParam(r, "id")
	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		TechStack   map[string]string `json:"tech_stack"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "name is required")
		return
	}
	ms, err := h.deps.Graph.CreateMicroservice(r.Context(), domain.Microservice{
		ProductID:   productID,
		Name:        req.Name,
		Description: req.Description,
		TechStack:   req.TechStack,
	})
	if err != nil {
		writeAssetGraphError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"id":         ms.ID,
		"product_id": ms.ProductID,
		"name":       ms.Name,
	})
}

// CreateDeployment handles POST /api/v1/microservices/{id}/deployments.
func (h *Handler) CreateDeployment(w http.ResponseWriter, r *http.Request) {
	if h.deps.Graph == nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "asset graph unavailable")
		return
	}
	microserviceID := chi.URLParam(r, "id")
	var req struct {
		Environment string `json:"environment"`
		Region      string `json:"region"`
		CustomerID  string `json:"customer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Environment == "" || req.CustomerID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "environment and customer_id are required")
		return
	}
	dep, err := h.deps.Graph.CreateDeployment(r.Context(), domain.Deployment{
		MicroserviceID: microserviceID,
		CustomerID:     req.CustomerID,
		Environment:    req.Environment,
		Region:         req.Region,
	})
	if err != nil {
		writeAssetGraphError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"id":              dep.ID,
		"microservice_id": dep.MicroserviceID,
		"customer_id":     dep.CustomerID,
		"environment":     dep.Environment,
	})
}

// CreateCustomer handles POST /api/v1/customers.
func (h *Handler) CreateCustomer(w http.ResponseWriter, r *http.Request) {
	if h.deps.Graph == nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "asset graph unavailable")
		return
	}
	var req struct {
		Name                    string            `json:"name"`
		ContactEmail            string            `json:"contact_email"`
		NotificationPreferences map[string]string `json:"notification_preferences"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.ContactEmail == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "name and contact_email are required")
		return
	}
	customer, err := h.deps.Graph.CreateCustomer(r.Context(), domain.Customer{
		Name:                    req.Name,
		ContactEmail:            req.ContactEmail,
		NotificationPreferences: req.NotificationPreferences,
	})
	if err != nil {
		writeAssetGraphError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"id":            customer.ID,
		"name":          customer.Name,
		"contact_email": customer.ContactEmail,
	})
}

// GetProductBlastRadius handles GET /api/v1/products/{id}/blast-radius.
func (h *Handler) GetProductBlastRadius(w http.ResponseWriter, r *http.Request) {
	if h.deps.Graph == nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "asset graph unavailable")
		return
	}
	productID := chi.URLParam(r, "id")
	result, err := h.deps.Graph.ProductBlastRadius(r.Context(), productID, r.URL.Query().Get("vulnerability_id"), r.URL.Query().Get("component_id"))
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "blast-radius query failed")
		return
	}
	teams := make([]map[string]string, 0, len(result.CustomerIDs))
	for _, customerID := range result.CustomerIDs {
		name := customerID
		if customer, err := h.deps.Graph.GetCustomer(r.Context(), customerID); err == nil {
			name = customer.Name
		}
		teams = append(teams, map[string]string{"id": customerID, "name": name})
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"product_id":            productID,
		"blast_radius_score":    result.Score,
		"affected_teams":        teams,
		"unique_customer_count": len(result.CustomerIDs),
	})
}

func writeAssetGraphError(w http.ResponseWriter, r *http.Request, err error) {
	RespondError(w, r, err)
}
