package api

import (
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/adapter/api/gen"
	"github.com/themis-project/themis/internal/domain"
)

func (h *Handler) ListProducts(w http.ResponseWriter, r *http.Request, params gen.ListProductsParams) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	scope := ""
	if len(principal.Scopes) == 1 && hasProductScope(principal.Scopes[0]) {
		scope = productIDFromScope(principal.Scopes[0])
	}
	items, page, err := h.deps.Catalog.ListProducts(ctx, PageFromParams(params.Cursor, params.Limit), scope)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, toProductList(items, page))
}

func (h *Handler) CreateProduct(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok || !AuthorizeWriteConfig(principal) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "admin scope required")
		return
	}
	var req gen.CreateProductRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid JSON body")
		return
	}
	product, err := h.deps.Catalog.CreateProduct(ctx, req.Name, derefString(req.Description))
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusCreated, toProduct(product))
}

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request, id gen.ProductID, params gen.ListProjectsParams) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	if !AuthorizeProduct(principal, id.String()) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "product scope mismatch")
		return
	}
	items, page, err := h.deps.Catalog.ListProjects(ctx, id.String(), PageFromParams(params.Cursor, params.Limit))
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "product not found")
		return
	}
	WriteJSON(w, http.StatusOK, toProjectList(items, page))
}

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request, id gen.ProductID) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok || !AuthorizeProduct(principal, id.String()) || !AuthorizeWriteConfig(principal) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "insufficient scope")
		return
	}
	var req gen.CreateProjectRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid JSON body")
		return
	}
	project, err := h.deps.Catalog.CreateProject(ctx, id.String(), req.Name, derefString(req.Description))
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", err.Error())
		return
	}
	WriteJSON(w, http.StatusCreated, toProject(project))
}

func (h *Handler) ListProductVersions(w http.ResponseWriter, r *http.Request, id gen.ProductID, params gen.ListProductVersionsParams) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok || !AuthorizeProduct(principal, id.String()) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "product scope mismatch")
		return
	}
	items, page, err := h.deps.Catalog.ListProductVersions(ctx, id.String(), PageFromParams(params.Cursor, params.Limit))
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "product not found")
		return
	}
	WriteJSON(w, http.StatusOK, toProductVersionList(items, page))
}

func (h *Handler) ListProjectScans(w http.ResponseWriter, r *http.Request, id gen.ProjectID, params gen.ListProjectScansParams) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	productID, err := h.deps.Scans.GetProjectProductID(ctx, id.String())
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "project not found")
		return
	}
	if !AuthorizeProduct(principal, productID) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "product scope mismatch")
		return
	}
	items, page, err := h.deps.Scans.ListProjectScans(ctx, id.String(), PageFromParams(params.Cursor, params.Limit))
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, toScanList(items, page))
}

func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request, id gen.ScanID) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	scan, err := h.deps.Scans.GetScan(ctx, id.String())
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "scan not found")
		return
	}
	if !AuthorizeProduct(principal, scan.ProductID) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "product scope mismatch")
		return
	}
	WriteJSON(w, http.StatusOK, toScanDetail(scan))
}

func (h *Handler) ListScanVulnerabilities(w http.ResponseWriter, r *http.Request, id gen.ScanID, params gen.ListScanVulnerabilitiesParams) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	scan, err := h.deps.Scans.GetScan(ctx, id.String())
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "scan not found")
		return
	}
	if !AuthorizeProduct(principal, scan.ProductID) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "product scope mismatch")
		return
	}
	filter := domain.ScanVulnerabilityFilter{}
	if params.Severity != nil {
		filter.Severity = string(*params.Severity)
	}
	if params.EffectiveState != nil {
		filter.EffectiveState = *params.EffectiveState
	}
	if params.CveId != nil {
		filter.CVEID = *params.CveId
	}
	items, page, err := h.deps.Scans.ListScanVulnerabilities(ctx, id.String(), filter, PageFromParams(params.Cursor, params.Limit))
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, toScanVulnerabilityList(items, page))
}

func (h *Handler) ListComponents(w http.ResponseWriter, r *http.Request, params gen.ListComponentsParams) {
	ctx := r.Context()
	if _, ok := AuthFromContext(ctx); !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	purl := derefString(params.Purl)
	productID := ""
	if params.ProductId != nil {
		productID = params.ProductId.String()
	}
	items, page, err := h.deps.Components.ListComponents(ctx, purl, productID, PageFromParams(params.Cursor, params.Limit))
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, toComponentList(items, page))
}

func (h *Handler) ListCVEWatchFindings(w http.ResponseWriter, r *http.Request, params gen.ListCVEWatchFindingsParams) {
	ctx := r.Context()
	if _, ok := AuthFromContext(ctx); !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	productID := ""
	if params.ProductId != nil {
		productID = params.ProductId.String()
	}
	severity := derefString(params.Severity)
	items, page, err := h.deps.Watch.ListFindings(ctx, productID, severity, PageFromParams(params.Cursor, params.Limit))
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, toCVEWatchList(items, page))
}

func (h *Handler) GetNotificationConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, ok := AuthFromContext(ctx); !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	rules, err := h.deps.Notifications.ListRules(ctx)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, gen.NotificationConfig{Rules: ptrRules(toNotificationRules(rules))})
}

func (h *Handler) UpdateNotificationConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok || !AuthorizeWriteConfig(principal) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "admin scope required")
		return
	}
	var req gen.NotificationConfig
	if err := decodeJSON(r, &req); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid JSON body")
		return
	}
	rules := fromNotificationRules(req.Rules)
	if err := h.deps.Notifications.ReplaceRules(ctx, rules); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, req)
}

func (h *Handler) GetScannerConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if _, ok := AuthFromContext(ctx); !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	settings, err := h.deps.Scanners.Get(ctx)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, toScannerConfig(settings))
}

func (h *Handler) UpdateScannerConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok || !AuthorizeWriteConfig(principal) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "admin scope required")
		return
	}
	var req gen.ScannerConfig
	if err := decodeJSON(r, &req); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid JSON body")
		return
	}
	settings := fromScannerConfig(req)
	if err := h.deps.Scanners.Save(ctx, settings); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, req)
}

func (h *Handler) SubmitTriage(w http.ResponseWriter, r *http.Request, id gen.VulnerabilityFindingID) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	productID, err := h.deps.TriageRepo.GetFindingScope(ctx, id.String())
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "finding not found")
		return
	}
	if !AuthorizeProduct(principal, productID) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "product scope mismatch")
		return
	}
	var req gen.TriageRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid JSON body")
		return
	}
	decision, err := h.deps.Triage.Submit(ctx, domain.TriageDecision{
		FindingID:     id.String(),
		Decision:      string(req.Decision),
		Justification: req.Justification,
		AcceptedUntil: req.AcceptedUntil,
		AssignedTo:    derefString(req.AssignedTo),
		Actor:         principal.KeyID,
	})
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, gen.TriageResponse{
		FindingId:      openapi_types.UUID(parseUUID(id.String())),
		EffectiveState: decision.EffectiveState,
	})
}

func (h *Handler) GetTriageHistory(w http.ResponseWriter, r *http.Request, id gen.VulnerabilityFindingID, params gen.GetTriageHistoryParams) {
	ctx := r.Context()
	if _, ok := AuthFromContext(ctx); !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	items, page, err := h.deps.Triage.History(ctx, id.String(), PageFromParams(params.Cursor, params.Limit))
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "finding not found")
		return
	}
	WriteJSON(w, http.StatusOK, toTriageHistoryList(items, page))
}

func decodeJSON(r *http.Request, dst any) error {
	return jsonNewDecoder(r.Body, dst)
}

func hasProductScope(scope string) bool {
	return len(scope) > len(domain.ProductScopePrefix) && scope[:len(domain.ProductScopePrefix)] == domain.ProductScopePrefix
}

func productIDFromScope(scope string) string {
	return scope[len(domain.ProductScopePrefix):]
}

func parseUUID(id string) openapi_types.UUID {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return openapi_types.UUID{}
	}
	var out openapi_types.UUID
	copy(out[:], parsed[:])
	return out
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
