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

// The build profile of a Project and of a Release (EDR-REBUILD-01 D10, D16; step R2a). Writing
// one is a product write, like tags: admin, or a key scoped to the owning product. The profile
// travels as raw JSON in both directions, so what is served is byte for byte what is stored.

// buildProfileBodyLimit bounds the request body. It is well above the 16 KiB a profile may
// have, so that a profile that is too large is answered by the domain's own message.
const buildProfileBodyLimit = 64 * 1024

func (h *Handler) GetProjectBuildProfile(w http.ResponseWriter, r *http.Request, id string) {
	h.getBuildProfile(w, r, domain.TagProject, id)
}

func (h *Handler) GetReleaseBuildProfile(w http.ResponseWriter, r *http.Request, id string) {
	h.getBuildProfile(w, r, domain.TagRelease, id)
}

func (h *Handler) PutProjectBuildProfile(w http.ResponseWriter, r *http.Request, id string) {
	if !h.authorizeProject(w, r, id) {
		return
	}
	h.putBuildProfile(w, r, domain.TagProject, id)
}

func (h *Handler) PutReleaseBuildProfile(w http.ResponseWriter, r *http.Request, id string) {
	if !h.authorizeProject(w, r, h.projectOfRelease(r, id)) {
		return
	}
	h.putBuildProfile(w, r, domain.TagRelease, id)
}

func (h *Handler) DeleteProjectBuildProfile(w http.ResponseWriter, r *http.Request, id string, params gen.DeleteProjectBuildProfileParams) {
	if !h.authorizeProject(w, r, id) {
		return
	}
	h.deleteBuildProfile(w, r, domain.TagProject, id, params.Actor)
}

func (h *Handler) DeleteReleaseBuildProfile(w http.ResponseWriter, r *http.Request, id string, params gen.DeleteReleaseBuildProfileParams) {
	if !h.authorizeProject(w, r, h.projectOfRelease(r, id)) {
		return
	}
	h.deleteBuildProfile(w, r, domain.TagRelease, id, params.Actor)
}

// projectOfRelease names the project a release belongs to, "" when it cannot be read. A
// confined key is then refused, and an admin key gets the service's own "not found".
func (h *Handler) projectOfRelease(r *http.Request, releaseID string) string {
	rel, err := h.svc.GetRelease(r.Context(), domain.ReleaseID(releaseID))
	if err != nil {
		return ""
	}
	return string(rel.ProjectID())
}

// GetReleaseResolvedBuildProfile handles GET /releases/{id}/build-profile/resolved.
func (h *Handler) GetReleaseResolvedBuildProfile(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.svc.ResolvedBuildProfile(r.Context(), id)
	if err != nil {
		writeBuildProfileError(w, err)
		return
	}
	out := gen.ResolvedBuildProfile{ReleaseId: res.ReleaseID, ProjectId: res.ProjectID, Found: res.Found}
	if res.Found {
		scope := gen.ResolvedBuildProfileScope(res.Record.Level)
		rec := toBuildProfileRecord(res.Record)
		out.Scope, out.Record = &scope, &rec
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getBuildProfile(w http.ResponseWriter, r *http.Request, level domain.BuildProfileLevel, id string) {
	hist, err := h.svc.BuildProfileHistory(r.Context(), level, id)
	if err != nil {
		writeBuildProfileError(w, err)
		return
	}
	out := gen.BuildProfileHistory{History: make([]gen.BuildProfileRecord, 0, len(hist))}
	for _, rec := range hist {
		out.History = append(out.History, toBuildProfileRecord(rec))
	}
	if len(hist) > 0 && !hist[0].Removed {
		out.Current = &out.History[0]
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) putBuildProfile(w http.ResponseWriter, r *http.Request, level domain.BuildProfileLevel, id string) {
	var body gen.BuildProfilePut
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, buildProfileBodyLimit)).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	rec, err := h.svc.SetBuildProfile(r.Context(), level, id, body.Profile, body.Actor, keyName(r))
	if err != nil {
		writeBuildProfileError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toBuildProfileRecord(rec))
}

func (h *Handler) deleteBuildProfile(w http.ResponseWriter, r *http.Request, level domain.BuildProfileLevel, id, actor string) {
	rec, err := h.svc.RemoveBuildProfile(r.Context(), level, id, actor, keyName(r))
	if err != nil {
		writeBuildProfileError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toBuildProfileRecord(rec))
}

// keyName is the name of the API key behind the request, "" with auth off.
func keyName(r *http.Request) string {
	p, _ := auth.PrincipalFrom(r.Context())
	return p.Name
}

func toBuildProfileRecord(r domain.BuildProfileRecord) gen.BuildProfileRecord {
	out := gen.BuildProfileRecord{
		Level: gen.BuildProfileRecordLevel(r.Level), EntityId: r.EntityID, Revision: r.Revision,
		Removed: r.Removed, Actor: r.Actor, RecordedAt: r.At,
	}
	if !r.Removed {
		profile := gen.BuildProfile(r.Profile)
		sum := r.SHA256()
		out.Profile, out.Sha256 = &profile, &sum
	}
	if r.Via != "" {
		via := r.Via
		out.Via = &via
	}
	return out
}

func writeBuildProfileError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidBuildProfile):
		writeProblem(w, http.StatusBadRequest, "invalid build profile", err.Error())
	case errors.Is(err, app.ErrBuildProfilesUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "build profiles unavailable", err.Error())
	case errors.Is(err, app.ErrNoBuildProfile),
		errors.Is(err, app.ErrUnknownProject), errors.Is(err, app.ErrUnknownRelease):
		writeProblem(w, http.StatusNotFound, "not found", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "build profile", err.Error())
	}
}
