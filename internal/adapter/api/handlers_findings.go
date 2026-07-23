package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/domain"
)

// Scoped vulnerability listings roll the per-scan findings up to a product, project,
// or product version (latest scan per artifact, via v_latest_findings). They return
// the same ScanVulnerabilityList shape and filters as GET /scans/{id}/vulnerabilities;
// the same CVE/component may appear once per artifact under the scope (each artifact
// is a distinct deployment — the risk_context identity).

// ListProductVulnerabilities handles GET /api/v1/products/{id}/vulnerabilities.
func (h *Handler) ListProductVulnerabilities(w http.ResponseWriter, r *http.Request) {
	productID := chi.URLParam(r, "id")
	h.writeScopedVulnerabilities(w, r, domain.FindingScope{Kind: domain.FindingScopeProduct, ProductID: productID}, productID)
}

// ListProductVersionVulnerabilities handles GET /api/v1/products/{id}/versions/{v}/vulnerabilities.
func (h *Handler) ListProductVersionVulnerabilities(w http.ResponseWriter, r *http.Request) {
	productID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "v")
	h.writeScopedVulnerabilities(w, r, domain.FindingScope{Kind: domain.FindingScopeVersion, ProductID: productID, Version: version}, productID)
}

// ListProjectVulnerabilities handles GET /api/v1/projects/{id}/vulnerabilities.
func (h *Handler) ListProjectVulnerabilities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, ok := AuthFromContext(ctx); !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	projectID := chi.URLParam(r, "id")
	productID, err := h.deps.Scans.GetProjectProductID(ctx, projectID)
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "project not found")
		return
	}
	h.writeScopedVulnerabilities(w, r, domain.FindingScope{Kind: domain.FindingScopeProject, ProjectID: projectID}, productID)
}

// writeScopedVulnerabilities authorizes against productID, runs the scoped finding
// query, and writes the ScanVulnerabilityList. The caller supplies the productID
// (a URL param for product/version scopes; the project's product for project scope).
func (h *Handler) writeScopedVulnerabilities(w http.ResponseWriter, r *http.Request, scope domain.FindingScope, productID string) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	if !AuthorizeProduct(principal, productID) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "product scope mismatch")
		return
	}
	filter, page := scopedVulnerabilityRequest(r)
	items, next, err := h.deps.Scans.ListScopedVulnerabilities(ctx, scope, filter, page)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, toScanVulnerabilityList(items, next))
}

// scopedVulnerabilityRequest reads the shared severity/effective_state/cve_id filters
// and cursor/limit pagination from the query string.
func scopedVulnerabilityRequest(r *http.Request) (domain.ScanVulnerabilityFilter, domain.PageRequest) {
	q := r.URL.Query()
	filter := domain.ScanVulnerabilityFilter{
		Severity:       q.Get("severity"),
		EffectiveState: q.Get("effective_state"),
		CVEID:          q.Get("cve_id"),
	}
	page := domain.PageRequest{Cursor: q.Get("cursor"), Limit: 50}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		if n > 100 {
			n = 100
		}
		page.Limit = n
	}
	return filter, page
}
