package http

import (
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/communication/adapters/http/gen"
	"github.com/themis-project/themis/internal/communication/app"
)

// GetRemediationMetricsReport renders the remediation-metrics report (EDR-REMEDIATION-01 D6).
// A Governance failure is a 502: the figures live there, and this node only renders them.
func (h *Handler) GetRemediationMetricsReport(w http.ResponseWriter, r *http.Request, params gen.GetRemediationMetricsReportParams) {
	if h.reports == nil {
		writeProblem(w, http.StatusServiceUnavailable, "report unavailable", "the remediation report is not wired on this node")
		return
	}
	product, format := "", ""
	if params.Product != nil {
		product = *params.Product
	}
	if params.Format != nil {
		format = *params.Format
	}
	body, contentType, err := h.reports.Render(r.Context(), product, format)
	switch {
	case errors.Is(err, app.ErrUnknownReportFormat):
		writeProblem(w, http.StatusBadRequest, "unknown format", err.Error())
		return
	case err != nil:
		writeProblem(w, http.StatusBadGateway, "governance read failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
