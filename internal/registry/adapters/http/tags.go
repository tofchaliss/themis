package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/registry/adapters/http/gen"
	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// Tags on Product, Project and Release (EDR-REMEDIATION-01 D7) — filters only, never a weight.
// Writing them is a product write: admin, or a key scoped to the owning product.

func (h *Handler) GetProductTags(w http.ResponseWriter, r *http.Request, id string) {
	h.getTags(w, r, domain.TagProduct, id)
}

func (h *Handler) GetProjectTags(w http.ResponseWriter, r *http.Request, id string) {
	h.getTags(w, r, domain.TagProject, id)
}

func (h *Handler) GetReleaseTags(w http.ResponseWriter, r *http.Request, id string) {
	h.getTags(w, r, domain.TagRelease, id)
}

func (h *Handler) PutProductTags(w http.ResponseWriter, r *http.Request, id string) {
	if !authorizeProduct(w, r, id) {
		return
	}
	h.putTags(w, r, domain.TagProduct, id)
}

func (h *Handler) PutProjectTags(w http.ResponseWriter, r *http.Request, id string) {
	if !h.authorizeProject(w, r, id) {
		return
	}
	h.putTags(w, r, domain.TagProject, id)
}

func (h *Handler) PutReleaseTags(w http.ResponseWriter, r *http.Request, id string) {
	project := ""
	if rel, err := h.svc.GetRelease(r.Context(), domain.ReleaseID(id)); err == nil {
		project = string(rel.ProjectID())
	}
	if !h.authorizeProject(w, r, project) {
		return
	}
	h.putTags(w, r, domain.TagRelease, id)
}

func (h *Handler) getTags(w http.ResponseWriter, r *http.Request, kind domain.TagEntity, id string) {
	ts, err := h.svc.Tags(r.Context(), kind, id)
	if err != nil {
		writeTagError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, gen.TagSet{Tags: ts.Own, Effective: ts.Effective})
}

func (h *Handler) putTags(w http.ResponseWriter, r *http.Request, kind domain.TagEntity, id string) {
	var body gen.TagsPut
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if _, err := h.svc.SetTags(r.Context(), kind, id, body.Tags); err != nil {
		writeTagError(w, err)
		return
	}
	h.getTags(w, r, kind, id)
}

func writeTagError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidTag):
		writeProblem(w, http.StatusBadRequest, "invalid tags", err.Error())
	case errors.Is(err, app.ErrUnknownProduct), errors.Is(err, app.ErrUnknownProject), errors.Is(err, app.ErrUnknownRelease):
		writeProblem(w, http.StatusNotFound, "not found", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "tags", err.Error())
	}
}

// tagFilter keeps the ids whose effective tags carry tag, and returns every id's own tags. The
// parents' tags are passed in (a product list has none; a project list its product's; a release
// list its project's effective set).
func (h *Handler) tagFilter(r *http.Request, kind domain.TagEntity, ids []string, parents []string, tag string) (map[string][]string, map[string]bool, error) {
	own, err := h.svc.OwnTags(r.Context(), kind, ids)
	if err != nil {
		return nil, nil, err
	}
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = domain.HasTag(domain.UnionTags(own[id], parents), tag)
	}
	return own, keep, nil
}

func tagsPtr(t []string) *[]string {
	if len(t) == 0 {
		return nil
	}
	return &t
}

// ListTaggedReleases handles GET /tagged-releases?tag= — every release whose effective tags carry
// the tag, in one read (EDR-REMEDIATION-01 D7, the What's new filter).
func (h *Handler) ListTaggedReleases(w http.ResponseWriter, r *http.Request, params gen.ListTaggedReleasesParams) {
	rels, err := h.svc.TaggedReleases(r.Context(), params.Tag)
	if err != nil {
		writeTagError(w, err)
		return
	}
	out := make([]gen.ReleaseView, 0, len(rels))
	for _, rel := range rels {
		rid, proj, ver := string(rel.ID()), string(rel.ProjectID()), rel.Version()
		out = append(out, gen.ReleaseView{Id: &rid, ProjectId: &proj, Version: &ver})
	}
	writeJSON(w, http.StatusOK, out)
}
