package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/usecase/vexgen"
)

// GetProductVersionVEX handles GET /api/v1/products/{id}/versions/{v}/vex.
func (h *Handler) GetProductVersionVEX(w http.ResponseWriter, r *http.Request) {
	if h.deps.VEXExport == nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "vex export unavailable")
		return
	}
	productID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "v")
	format := vexgen.ParseExportFormat(r.URL.Query().Get("format"))
	if r.URL.Query().Get("format") == "" {
		format = vexgen.FormatFromAccept(r.Header.Get("Accept"))
	}

	body, err := h.deps.VEXExport.ExportVEX(r.Context(), productID, version, format)
	if err != nil {
		writeVEXExportError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// GetProductVersionVEXCoverage handles GET /api/v1/products/{id}/versions/{v}/vex-coverage.
func (h *Handler) GetProductVersionVEXCoverage(w http.ResponseWriter, r *http.Request) {
	if h.deps.VEXExport == nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "vex export unavailable")
		return
	}
	productID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "v")
	summary, err := h.deps.VEXExport.ExportCoverage(r.Context(), productID, version)
	if err != nil {
		writeVEXExportError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]int{
		"covered":       summary.Covered,
		"not_covered":   summary.NotCovered,
		"purl_mismatch": summary.PURLMismatch,
	})
}

func writeVEXExportError(w http.ResponseWriter, r *http.Request, err error) {
	RespondError(w, r, err)
}
