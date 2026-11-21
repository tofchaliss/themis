package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/registry/adapters/http/gen"
	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// CVSS security requirements CR / IR / AR (EDR-SCORING-01 S3). Writing them is a product write,
// like tags: admin, or a key scoped to the owning product.

func (h *Handler) GetProductRequirements(w http.ResponseWriter, r *http.Request, id string) {
	h.getRequirements(w, r, domain.TagProduct, id)
}

func (h *Handler) GetProjectRequirements(w http.ResponseWriter, r *http.Request, id string) {
	h.getRequirements(w, r, domain.TagProject, id)
}

func (h *Handler) GetReleaseRequirements(w http.ResponseWriter, r *http.Request, id string) {
	h.getRequirements(w, r, domain.TagRelease, id)
}

func (h *Handler) PostProductRequirements(w http.ResponseWriter, r *http.Request, id string) {
	if !authorizeProduct(w, r, id) {
		return
	}
	h.postRequirements(w, r, domain.TagProduct, id)
}

func (h *Handler) PostProjectRequirements(w http.ResponseWriter, r *http.Request, id string) {
	if !h.authorizeProject(w, r, id) {
		return
	}
	h.postRequirements(w, r, domain.TagProject, id)
}

func (h *Handler) PostReleaseRequirements(w http.ResponseWriter, r *http.Request, id string) {
	project := ""
	if rel, err := h.svc.GetRelease(r.Context(), domain.ReleaseID(id)); err == nil {
		project = string(rel.ProjectID())
	}
	if !h.authorizeProject(w, r, project) {
		return
	}
	h.postRequirements(w, r, domain.TagRelease, id)
}

// GetReleaseResolvedRequirements handles GET /releases/{id}/requirements/resolved.
func (h *Handler) GetReleaseResolvedRequirements(w http.ResponseWriter, r *http.Request, id string) {
	rr, err := h.svc.ResolvedRequirements(r.Context(), id)
	if err != nil {
		writeRequirementError(w, err)
		return
	}
	res := func(v domain.ResolvedRequirement) gen.ResolvedRequirement {
		return gen.ResolvedRequirement{Value: gen.RequirementValue(v.Value), Level: gen.ResolvedRequirementLevel(v.Level)}
	}
	writeJSON(w, http.StatusOK, gen.ResolvedRequirements{
		Cr: res(rr.Resolved.CR), Ir: res(rr.Resolved.IR), Ar: res(rr.Resolved.AR),
		Release: recordPtr(rr.Release), Project: recordPtr(rr.Project), Product: recordPtr(rr.Product),
	})
}

func (h *Handler) getRequirements(w http.ResponseWriter, r *http.Request, level domain.RequirementLevel, id string) {
	hist, err := h.svc.RequirementHistory(r.Context(), level, id)
	if err != nil {
		writeRequirementError(w, err)
		return
	}
	out := gen.RequirementHistory{History: make([]gen.RequirementRecord, 0, len(hist))}
	for _, rec := range hist {
		out.History = append(out.History, toRecord(rec))
	}
	if len(hist) > 0 {
		out.Current = &out.History[0]
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) postRequirements(w http.ResponseWriter, r *http.Request, level domain.RequirementLevel, id string) {
	var body gen.RequirementChange
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	change := app.RequirementChange{CR: valueOf(body.Cr), IR: valueOf(body.Ir), AR: valueOf(body.Ar), Reason: body.Reason, Actor: body.Actor}
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		change.Via = p.Name
	}
	rec, err := h.svc.SetRequirements(r.Context(), level, id, change)
	if err != nil {
		writeRequirementError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toRecord(rec))
}

func valueOf(v *gen.RequirementValue) string {
	if v == nil {
		return ""
	}
	return string(*v)
}

func toRecord(r domain.RequirementRecord) gen.RequirementRecord {
	out := gen.RequirementRecord{
		Level: gen.RequirementRecordLevel(r.Level), EntityId: r.EntityID, Cr: gen.RequirementValue(r.Requirements.CR),
		Ir: gen.RequirementValue(r.Requirements.IR), Ar: gen.RequirementValue(r.Requirements.AR),
		Reason: r.Reason, Actor: r.Actor, RecordedAt: r.At,
	}
	if r.Via != "" {
		via := r.Via
		out.Via = &via
	}
	return out
}

func recordPtr(r *domain.RequirementRecord) *gen.RequirementRecord {
	if r == nil {
		return nil
	}
	rec := toRecord(*r)
	return &rec
}

func writeRequirementError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidRequirement):
		writeProblem(w, http.StatusBadRequest, "invalid security requirements", err.Error())
	case errors.Is(err, app.ErrRequirementsUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "security requirements unavailable", err.Error())
	case errors.Is(err, app.ErrUnknownProduct), errors.Is(err, app.ErrUnknownProject), errors.Is(err, app.ErrUnknownRelease):
		writeProblem(w, http.StatusNotFound, "not found", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "security requirements", err.Error())
	}
}
