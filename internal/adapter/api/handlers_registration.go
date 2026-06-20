package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// CreateVersion handles POST /api/v1/projects/{id}/versions.
func (h *Handler) CreateVersion(w http.ResponseWriter, r *http.Request) {
	if h.deps.Catalog == nil {
		WriteCatalogError(w, http.StatusInternalServerError, CodeInternalError)
		return
	}
	projectID := chi.URLParam(r, "id")
	var req struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Version) == "" {
		WriteCatalogError(w, http.StatusBadRequest, CodeInvalidRequest)
		return
	}
	version, err := h.deps.Catalog.CreateVersion(r.Context(), projectID, strings.TrimSpace(req.Version))
	if err != nil {
		RespondError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"id":         version.ID,
		"project_id": version.ProjectID,
		"version":    version.Version,
	})
}

// RegisterArtifact handles POST /api/v1/products/{id}/artifacts.
func (h *Handler) RegisterArtifact(w http.ResponseWriter, r *http.Request) {
	if h.deps.Catalog == nil {
		WriteCatalogError(w, http.StatusInternalServerError, CodeInternalError)
		return
	}
	productID := chi.URLParam(r, "id")
	var req struct {
		ImageDigest string `json:"image_digest"`
		Version     string `json:"version"`
		Repository  string `json:"repository"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ImageDigest) == "" {
		WriteCatalogError(w, http.StatusBadRequest, CodeInvalidRequest)
		return
	}
	artifact, err := h.deps.Catalog.RegisterArtifact(
		r.Context(), productID, strings.TrimSpace(req.Version),
		strings.TrimSpace(req.ImageDigest), strings.TrimSpace(req.Repository),
	)
	if err != nil {
		RespondError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"id":           artifact.ID,
		"version_id":   artifact.VersionID,
		"image_digest": artifact.ImageDigest,
	})
}
