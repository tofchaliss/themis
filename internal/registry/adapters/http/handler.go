// Package http exposes the registry over REST, implementing the oapi-codegen server
// interface (package gen) over the application service. It maps between wire models
// and the domain and renders a Problem error envelope (BCK-0048).
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/registry/adapters/http/gen"
	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// Handler implements gen.ServerInterface over the registry application service.
type Handler struct {
	svc *app.RegistryService
}

// NewHandler builds a Handler.
func NewHandler(svc *app.RegistryService) *Handler { return &Handler{svc: svc} }

// Router returns an http.Handler serving the registry routes; mount it under the
// OpenAPI base path (/api/v1).
func (h *Handler) Router() http.Handler { return gen.Handler(h) }

// RegisterProduct handles POST /products.
func (h *Handler) RegisterProduct(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterProductRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	id, err := h.svc.RegisterProduct(r.Context(), req.Name)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.RegisterResponse{Id: string(id)})
}

// RegisterProject handles POST /projects.
func (h *Handler) RegisterProject(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	id, err := h.svc.RegisterProject(r.Context(), domain.ProductID(req.ProductId), req.Name)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.RegisterResponse{Id: string(id)})
}

// RegisterRelease handles POST /releases.
func (h *Handler) RegisterRelease(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	id, err := h.svc.RegisterRelease(r.Context(), domain.ProjectID(req.ProjectId), req.Version)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.RegisterResponse{Id: string(id)})
}

// GetRelease handles GET /releases/{id}.
func (h *Handler) GetRelease(w http.ResponseWriter, r *http.Request, id string) {
	rel, err := h.svc.GetRelease(r.Context(), domain.ReleaseID(id))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "release not found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "cannot read release", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toRelease(rel))
}

// ListReleases handles GET /releases?project=.
func (h *Handler) ListReleases(w http.ResponseWriter, r *http.Request, params gen.ListReleasesParams) {
	rels, err := h.svc.ListReleases(r.Context(), domain.ProjectID(params.Project))
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot list releases", err.Error())
		return
	}
	out := make([]gen.Release, 0, len(rels))
	for _, rel := range rels {
		out = append(out, toRelease(rel))
	}
	writeJSON(w, http.StatusOK, out)
}

// --- error mapping + mappers -----------------------------------------------

func writeRegisterError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, app.ErrUnknownProduct):
		writeProblem(w, http.StatusUnprocessableEntity, "unknown product", err.Error())
	case errors.Is(err, app.ErrUnknownProject):
		writeProblem(w, http.StatusUnprocessableEntity, "unknown project", err.Error())
	default:
		writeProblem(w, http.StatusBadRequest, "cannot register", err.Error())
	}
}

func toRelease(r domain.Release) gen.Release {
	id, project, version := string(r.ID()), string(r.ProjectID()), r.Version()
	return gen.Release{Id: &id, ProjectId: &project, Version: &version}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	writeJSON(w, status, gen.Problem{Title: &title, Detail: &detail})
}
