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

// renameAdminDetail answers a non-admin key on PATCH /projects/{id}. A rename is an estate
// decision a person makes; a product-scoped CI key only ever needs find-or-create, and a bot
// that could rename would quietly move every upload's name.
const renameAdminDetail = "renaming a project requires an admin key"

// RenameProject handles PATCH /projects/{id} — correct a project's name (EDR-KERNEL-01 D5).
// The id, the product and everything keyed to the project stay as they are.
func (h *Handler) RenameProject(w http.ResponseWriter, r *http.Request, id string) {
	if _, confined := confinedPrincipal(r); confined {
		writeProblem(w, http.StatusForbidden, "unauthorized", renameAdminDetail)
		return
	}
	var body gen.RenameProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	p, _, err := h.svc.RenameProject(r.Context(), domain.ProjectID(id), body.Name)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, toProject(p))
	case errors.Is(err, app.ErrUnknownProject), errors.Is(err, store.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "project not found", err.Error())
	case errors.Is(err, app.ErrProjectNameTaken):
		writeProblem(w, http.StatusConflict, "name already taken",
			"another project of this product already has this name (names ignore case); nothing was changed")
	case errors.Is(err, domain.ErrEmptyProjectName):
		writeProblem(w, http.StatusBadRequest, "invalid name", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "cannot rename project", err.Error())
	}
}
