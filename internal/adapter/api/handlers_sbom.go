package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/domain"
)

// ListSBOMs handles GET /api/v1/sboms.
func (h *Handler) ListSBOMs(w http.ResponseWriter, r *http.Request) {
	if h.deps.SBOMMgmt == nil {
		WriteCatalogError(w, http.StatusInternalServerError, CodeInternalError)
		return
	}
	page := pageFromQuery(r)
	items, total, next, err := h.deps.SBOMMgmt.ListSBOMs(r.Context(), page)
	if err != nil {
		RespondError(w, r, err)
		return
	}
	writeSBOMList(w, items, total, next)
}

// ListProductSBOMs handles GET /api/v1/products/{id}/sboms.
func (h *Handler) ListProductSBOMs(w http.ResponseWriter, r *http.Request) {
	if h.deps.SBOMMgmt == nil {
		WriteCatalogError(w, http.StatusInternalServerError, CodeInternalError)
		return
	}
	productID := chi.URLParam(r, "id")
	page := pageFromQuery(r)
	items, total, next, err := h.deps.SBOMMgmt.ListProductSBOMs(r.Context(), productID, page)
	if err != nil {
		RespondError(w, r, err)
		return
	}
	writeSBOMList(w, items, total, next)
}

// DeleteSBOM handles DELETE /api/v1/sboms/{id}.
func (h *Handler) DeleteSBOM(w http.ResponseWriter, r *http.Request) {
	principal, ok := AuthFromContext(r.Context())
	if !ok || !AuthorizeWriteConfig(principal) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "write scope required; read-only keys cannot delete SBOMs")
		return
	}
	if h.deps.SBOMMgmt == nil {
		WriteCatalogError(w, http.StatusInternalServerError, CodeInternalError)
		return
	}
	id := chi.URLParam(r, "id")
	force := r.URL.Query().Get("force") == "true"
	summary, err := h.deps.SBOMMgmt.SoftDeleteSBOM(r.Context(), id, force)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrCannotDeleteLatestSBOM):
			WriteCatalogError(w, http.StatusConflict, CodeCannotDeleteLatestSBOM)
		case errors.Is(err, domain.ErrSBOMNotFound):
			WriteCatalogError(w, http.StatusNotFound, CodeSBOMNotFound)
		default:
			RespondError(w, r, err)
		}
		return
	}
	if h.deps.Audit != nil {
		details := map[string]string{"sbom_id": summary.SBOMID}
		actor := "system"
		if principal.KeyID != "" {
			actor = "api_key:" + principal.KeyID
			details["api_key_id"] = principal.KeyID
		}
		_ = h.deps.Audit.Record(r.Context(), domain.AuditEntry{
			Actor:        actor,
			Action:       domain.AuditActionSBOMDeleted,
			ResourceType: "sbom_document",
			ResourceID:   summary.SBOMID,
			Details:      details,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"sbom_id":         summary.SBOMID,
		"component_count": summary.ComponentCount,
		"finding_count":   summary.FindingCount,
		"deleted":         true,
	})
}

func pageFromQuery(r *http.Request) domain.PageRequest {
	page := domain.PageRequest{Limit: 50}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		page.Cursor = raw
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			page.Limit = n
		}
	}
	return page
}

func writeSBOMList(w http.ResponseWriter, items []domain.SBOMListEntry, total int, next domain.PageResult) {
	sboms := make([]map[string]any, 0, len(items))
	for _, item := range items {
		sboms = append(sboms, map[string]any{
			"id":                  item.ID,
			"product_name":        item.ProductName,
			"product_version":     item.ProductVersion,
			"image_name":          item.ImageName,
			"image_digest":        item.ImageDigest,
			"format":              item.Format,
			"component_count":     item.ComponentCount,
			"vulnerability_count": item.VulnerabilityCount,
			"uploaded_at":         item.UploadedAt,
			"is_latest":           item.IsLatest,
		})
	}
	var nextCursor any
	if next.NextCursor != "" {
		nextCursor = next.NextCursor
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"sboms":       sboms,
		"next_cursor": nextCursor,
		"total":       total,
	})
}
