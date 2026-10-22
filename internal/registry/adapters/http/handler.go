// Package http exposes the registry over REST, implementing the oapi-codegen server
// interface (package gen) over the application service. It maps between wire models
// and the domain and renders a Problem error envelope (BCK-0048).
package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/platform/auth"
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

// createdStatus is B4's status mapping for the three find-or-create routes: `201` when this
// request created the row, `200` when it already existed. The body's `created` flag carries
// the same answer, so a client that switches on the status and a client that reads the body
// cannot be told different stories.
func createdStatus(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

// RegisterProduct handles POST /products — find-or-create (EDR-INTAKE-01 B4).
func (h *Handler) RegisterProduct(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterProductRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if p, confined := confinedPrincipal(r); confined {
		h.registerOwnProduct(w, r, p, req.Name)
		return
	}
	id, created, err := h.svc.RegisterProduct(r.Context(), req.Name)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, createdStatus(created), gen.FindOrCreateResponse{Id: string(id), Created: created})
}

// RegisterProject handles POST /projects — find-or-create (EDR-INTAKE-01 B4).
func (h *Handler) RegisterProject(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if !authorizeProduct(w, r, req.ProductId) {
		return
	}
	id, created, err := h.svc.RegisterProject(r.Context(), domain.ProductID(req.ProductId), req.Name)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, createdStatus(created), gen.FindOrCreateResponse{Id: string(id), Created: created})
}

// RegisterRelease handles POST /releases — find-or-create (EDR-INTAKE-01 B4).
func (h *Handler) RegisterRelease(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if !h.authorizeProject(w, r, req.ProjectId) {
		return
	}
	id, created, err := h.svc.RegisterRelease(r.Context(), domain.ProjectID(req.ProjectId), req.Version)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, createdStatus(created), gen.FindOrCreateResponse{Id: string(id), Created: created})
}

// RegisterCustomer handles POST /customers.
func (h *Handler) RegisterCustomer(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterCustomerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	id, err := h.svc.RegisterCustomer(r.Context(), req.Name)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.RegisterResponse{Id: string(id)})
}

// RegisterMicroservice handles POST /products/{id}/microservices (id = product id).
func (h *Handler) RegisterMicroservice(w http.ResponseWriter, r *http.Request, id string) {
	var req gen.RegisterMicroserviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if !authorizeProduct(w, r, id) {
		return
	}
	msID, err := h.svc.RegisterMicroservice(r.Context(), domain.ProductID(id), req.Name)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.RegisterResponse{Id: string(msID)})
}

// RegisterDeployment handles POST /microservices/{id}/deployments (id = microservice id).
func (h *Handler) RegisterDeployment(w http.ResponseWriter, r *http.Request, id string) {
	var req gen.RegisterDeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	depID, err := h.svc.RegisterDeployment(r.Context(), domain.MicroserviceID(id), domain.CustomerID(req.CustomerId), req.Environment)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.RegisterResponse{Id: string(depID)})
}

// --- product confinement (EDR-SECURITY-01 D4) -------------------------------

// unauthorizedProductDetail is the one answer a product-scoped key gets for every write it
// may not make here: another product, a product or project that does not exist, and an
// ownership that could not be read. Like the intake door's refusal (EDR-INTAKE-01 B3), it is
// a constant, so a confined key learns nothing about the rest of the estate from it.
const unauthorizedProductDetail = "this key is not authorized for the product this request names; " +
	"a product-scoped key may register only under its own product"

// adminOnlyDetail answers a confined key on the estate-wide writes (customers, deployments),
// which belong to no single product.
const adminOnlyDetail = "this operation spans products and requires an admin key"

// confinedPrincipal returns the caller's principal when its writes are confined to its own
// product(s). An admin key is unconfined, and so is a node with auth disabled (no principal
// at all — the same posture every other route on that node has, and the reason
// THEMIS_AUTH_REQUIRED=1 exists). Every other key that reached a write here is confined:
// RequireWriteScope already refused read-only keys, so in practice this is a product:<id>
// key, and anything else falls closed with it.
func confinedPrincipal(r *http.Request) (auth.Principal, bool) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsAdmin() {
		return auth.Principal{}, false
	}
	return p, true
}

// authorizeProduct reports whether the request may write under productID, having written the
// 403 otherwise. An empty id is refused on its own account for a confined key, not left to
// the coincidence that no key carries the empty product.
func authorizeProduct(w http.ResponseWriter, r *http.Request, productID string) bool {
	p, confined := confinedPrincipal(r)
	if !confined {
		return true
	}
	if productID == "" || !p.AuthorizeProduct(productID) {
		writeProblem(w, http.StatusForbidden, "unauthorized", unauthorizedProductDetail)
		return false
	}
	return true
}

// authorizeProject reports whether the request may write under projectID, by the product
// that owns it. For a confined key an unknown project and an unreadable one are the same 403
// as a foreign one; an admin key keeps the service's own 422 unknown project.
func (h *Handler) authorizeProject(w http.ResponseWriter, r *http.Request, projectID string) bool {
	if _, confined := confinedPrincipal(r); !confined {
		return true
	}
	productID := ""
	if proj, err := h.svc.GetProject(r.Context(), domain.ProjectID(projectID)); err == nil {
		productID = string(proj.ProductID())
	}
	return authorizeProduct(w, r, productID)
}

// requireAdmin reports whether the request may make an estate-wide write, having written the
// 403 otherwise.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if _, confined := confinedPrincipal(r); confined {
		writeProblem(w, http.StatusForbidden, "unauthorized", adminOnlyDetail)
		return false
	}
	return true
}

// registerOwnProduct answers POST /products for a confined key. Such a key can never CREATE a
// product — a product key exists only because its product already does — but the
// find-or-create contract still holds for the product it owns: naming it (case-insensitively,
// as the uniqueness index compares) returns its existing id with 200, so a script that
// registers Product → Project → Release with a product key keeps working. Any other name is
// the same 403 whether or not that product exists.
func (h *Handler) registerOwnProduct(w http.ResponseWriter, r *http.Request, p auth.Principal, name string) {
	want := strings.TrimSpace(name)
	for _, scope := range p.Scopes {
		own, ok := strings.CutPrefix(scope, auth.ProductScopePrefix)
		if !ok || own == "" {
			continue
		}
		prod, err := h.svc.GetProduct(r.Context(), domain.ProductID(own))
		if err != nil {
			continue
		}
		if want != "" && strings.EqualFold(prod.Name(), want) {
			writeJSON(w, http.StatusOK, gen.FindOrCreateResponse{Id: string(prod.ID()), Created: false})
			return
		}
	}
	writeProblem(w, http.StatusForbidden, "unauthorized", unauthorizedProductDetail)
}

// GetBlastRadius handles GET /releases/{id}/blast-radius — unique customers reached (C1).
func (h *Handler) GetBlastRadius(w http.ResponseWriter, r *http.Request, id string) {
	n, err := h.svc.BlastRadius(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot compute blast radius", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, gen.BlastRadius{ReleaseId: id, UniqueCustomers: n})
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

// GetProject handles GET /projects/{id} — the upward hop of the name chain (D13.4).
func (h *Handler) GetProject(w http.ResponseWriter, r *http.Request, id string) {
	p, err := h.svc.GetProject(r.Context(), domain.ProjectID(id))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "project not found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "cannot read project", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toProject(p))
}

// GetProduct handles GET /products/{id} — the top of the name chain (D13.4).
func (h *Handler) GetProduct(w http.ResponseWriter, r *http.Request, id string) {
	p, err := h.svc.GetProduct(r.Context(), domain.ProductID(id))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "product not found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "cannot read product", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toProduct(p))
}

// ListReleases handles GET /releases?project=.
func (h *Handler) ListReleases(w http.ResponseWriter, r *http.Request, params gen.ListReleasesParams) {
	rels, err := h.svc.ListReleases(r.Context(), domain.ProjectID(params.Project))
	if err != nil {
		// An unknown project is a 404, not an empty 200 (DASH-1). This endpoint used to return an
		// empty list for a project that does not exist, which reads as "no releases yet" and is
		// the same confusion the new traversal endpoints were added to remove.
		if errors.Is(err, app.ErrUnknownProject) {
			writeProblem(w, http.StatusNotFound, "project not found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "cannot list releases", err.Error())
		return
	}
	out := make([]gen.Release, 0, len(rels))
	for _, rel := range rels {
		out = append(out, toRelease(rel))
	}
	writeJSON(w, http.StatusOK, out)
}

// ListProducts handles GET /products[?name=]. It is the entry point of the product → project →
// release traversal a human actually has (DASH-1): without it, a release's posture is reachable
// only by a caller that already holds the UUID `POST /releases` printed.
func (h *Handler) ListProducts(w http.ResponseWriter, r *http.Request, params gen.ListProductsParams) {
	prods, err := h.svc.ListProducts(r.Context(), strval(params.Name))
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot list products", err.Error())
		return
	}
	ids := make([]string, len(prods))
	for i, p := range prods {
		ids[i] = string(p.ID())
	}
	own, keep, err := h.tagFilter(r, domain.TagProduct, ids, nil, strval(params.Tag))
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot list products", err.Error())
		return
	}
	out := make([]gen.ProductView, 0, len(prods))
	for _, p := range prods {
		id, name := string(p.ID()), p.Name()
		if !keep[id] {
			continue
		}
		out = append(out, gen.ProductView{Id: &id, Name: &name, Tags: tagsPtr(own[id])})
	}
	writeJSON(w, http.StatusOK, out)
}

// ListProjectsOfProduct handles GET /products/{id}/projects[?name=].
func (h *Handler) ListProjectsOfProduct(w http.ResponseWriter, r *http.Request, id string, params gen.ListProjectsOfProductParams) {
	projs, err := h.svc.ListProjects(r.Context(), domain.ProductID(id), strval(params.Name))
	if err != nil {
		// "no such product" is a 404, not an empty 200. Collapsing them sends a caller hunting for
		// a typo in the wrong place.
		if errors.Is(err, app.ErrUnknownProduct) {
			writeProblem(w, http.StatusNotFound, "product not found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "cannot list projects", err.Error())
		return
	}
	ids := make([]string, len(projs))
	for i, p := range projs {
		ids[i] = string(p.ID())
	}
	parent, err := h.svc.Tags(r.Context(), domain.TagProduct, id)
	var own map[string][]string
	var keep map[string]bool
	if err == nil {
		own, keep, err = h.tagFilter(r, domain.TagProject, ids, parent.Effective, strval(params.Tag))
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot list projects", err.Error())
		return
	}
	out := make([]gen.ProjectView, 0, len(projs))
	for _, p := range projs {
		pid, prod, name := string(p.ID()), string(p.ProductID()), p.Name()
		if !keep[pid] {
			continue
		}
		out = append(out, gen.ProjectView{Id: &pid, ProductId: &prod, Name: &name, Tags: tagsPtr(own[pid])})
	}
	writeJSON(w, http.StatusOK, out)
}

// ListReleasesOfProject handles GET /projects/{id}/releases[?version=], completing the traversal.
func (h *Handler) ListReleasesOfProject(w http.ResponseWriter, r *http.Request, id string, params gen.ListReleasesOfProjectParams) {
	rels, err := h.svc.ListReleases(r.Context(), domain.ProjectID(id))
	if err != nil {
		if errors.Is(err, app.ErrUnknownProject) {
			writeProblem(w, http.StatusNotFound, "project not found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "cannot list releases", err.Error())
		return
	}
	// Version filtering is applied HERE rather than in the store: it is a presentation filter over
	// a list the store already returns whole, and pushing it down would add a second query shape
	// for no gain at this cardinality (a project has tens of releases, not millions).
	want := strval(params.Version)
	ids := make([]string, len(rels))
	for i, rel := range rels {
		ids[i] = string(rel.ID())
	}
	parent, err := h.svc.Tags(r.Context(), domain.TagProject, id)
	var own map[string][]string
	var keep map[string]bool
	if err == nil {
		own, keep, err = h.tagFilter(r, domain.TagRelease, ids, parent.Effective, strval(params.Tag))
	}
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot list releases", err.Error())
		return
	}
	out := make([]gen.ReleaseView, 0, len(rels))
	for _, rel := range rels {
		if want != "" && rel.Version() != want {
			continue
		}
		rid, proj, ver := string(rel.ID()), string(rel.ProjectID()), rel.Version()
		if !keep[rid] {
			continue
		}
		out = append(out, gen.ReleaseView{Id: &rid, ProjectId: &proj, Version: &ver, Tags: tagsPtr(own[rid])})
	}
	writeJSON(w, http.StatusOK, out)
}

// strval dereferences an optional query parameter; absent reads as "no filter".
func strval(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// --- error mapping + mappers -----------------------------------------------

func writeRegisterError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, app.ErrUnknownProduct):
		writeProblem(w, http.StatusUnprocessableEntity, "unknown product", err.Error())
	case errors.Is(err, app.ErrUnknownProject):
		writeProblem(w, http.StatusUnprocessableEntity, "unknown project", err.Error())
	case errors.Is(err, app.ErrUnknownMicroservice):
		writeProblem(w, http.StatusUnprocessableEntity, "unknown microservice", err.Error())
	case errors.Is(err, app.ErrUnknownCustomer):
		writeProblem(w, http.StatusUnprocessableEntity, "unknown customer", err.Error())
	default:
		writeProblem(w, http.StatusBadRequest, "cannot register", err.Error())
	}
}

func toRelease(r domain.Release) gen.Release {
	id, project, version := string(r.ID()), string(r.ProjectID()), r.Version()
	return gen.Release{Id: &id, ProjectId: &project, Version: &version}
}

func toProject(p domain.Project) gen.ProjectView {
	id, prod, name := string(p.ID()), string(p.ProductID()), p.Name()
	return gen.ProjectView{Id: &id, ProductId: &prod, Name: &name}
}

func toProduct(p domain.Product) gen.ProductView {
	id, name := string(p.ID()), p.Name()
	return gen.ProductView{Id: &id, Name: &name}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	writeJSON(w, status, gen.Problem{Title: &title, Detail: &detail})
}
