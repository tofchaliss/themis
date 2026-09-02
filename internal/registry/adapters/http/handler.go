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

// RegisterCustomer handles POST /customers.
func (h *Handler) RegisterCustomer(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterCustomerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
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
	depID, err := h.svc.RegisterDeployment(r.Context(), domain.MicroserviceID(id), domain.CustomerID(req.CustomerId), req.Environment)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.RegisterResponse{Id: string(depID)})
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
	out := make([]gen.ProductView, 0, len(prods))
	for _, p := range prods {
		id, name := string(p.ID()), p.Name()
		out = append(out, gen.ProductView{Id: &id, Name: &name})
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
	out := make([]gen.ProjectView, 0, len(projs))
	for _, p := range projs {
		pid, prod, name := string(p.ID()), string(p.ProductID()), p.Name()
		out = append(out, gen.ProjectView{Id: &pid, ProductId: &prod, Name: &name})
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
	out := make([]gen.ReleaseView, 0, len(rels))
	for _, rel := range rels {
		if want != "" && rel.Version() != want {
			continue
		}
		rid, proj, ver := string(rel.ID()), string(rel.ProjectID()), rel.Version()
		out = append(out, gen.ReleaseView{Id: &rid, ProjectId: &proj, Version: &ver})
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
