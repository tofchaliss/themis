package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/themis-project/themis/internal/knowledge/adapters/http/gen"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// The PSIRT bulletin register's HTTP edge (EDR-PSIRT-01 revision 3). Reads follow the node's
// read scope; a write needs the admin scope (R2), checked here because the inbound write gate
// also lets a product-scoped key write.

// unauthenticatedActor is recorded when auth is off on this node (dev): marked, never dressed
// up as a production identity.
const unauthenticatedActor = "unauthenticated"

// WithBulletins wires the bulletin register.
func (h *Handler) WithBulletins(b *app.BulletinService) *Handler {
	h.bulletins = b
	return h
}

// bulletinCaller is who asks: the edit rule's view of the key, and the actor the history
// records. No principal means auth is off on this node, where every caller may write.
func bulletinCaller(ctx context.Context) (domain.BulletinEditor, string) {
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return domain.BulletinEditor{Admin: true}, unauthenticatedActor
	}
	actor := unauthenticatedActor
	if p.KeyID != "" {
		actor = "key:" + p.KeyID
	}
	return domain.BulletinEditor{Admin: p.IsAdmin()}, actor
}

func toGenBulletin(b domain.Bulletin) gen.Bulletin {
	return gen.Bulletin{
		Id: b.ID, BulletinId: b.BulletinID, Title: b.Title, BulletinUrl: b.BulletinURL, AlertUrl: b.AlertURL,
		Note: b.Note, Cve: b.CVE, ReportDate: openapi_types.Date{Time: b.ReportDate}, Type: b.Type(),
		CreatedAt: b.CreatedAt, CreatedBy: b.CreatedBy, UpdatedAt: b.UpdatedAt, UpdatedBy: b.UpdatedBy,
	}
}

func fromGenBulletinInput(in gen.BulletinInput) domain.BulletinInput {
	val := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	out := domain.BulletinInput{
		BulletinID: in.BulletinId, Title: in.Title, BulletinURL: val(in.BulletinUrl), AlertURL: val(in.AlertUrl),
		Note: val(in.Note), CVE: val(in.Cve),
	}
	if in.ReportDate != nil {
		out.ReportDate = in.ReportDate.Time
	}
	return out
}

// writeBulletinError maps the register's refusals onto their statuses.
func writeBulletinError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, app.ErrBulletinsUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "no bulletin register wired", err.Error())
	case errors.Is(err, domain.ErrBulletinInvalid):
		writeProblem(w, http.StatusBadRequest, "invalid bulletin", err.Error())
	case errors.Is(err, app.ErrBulletinForbidden):
		writeProblem(w, http.StatusForbidden, "Forbidden", "changing the bulletin register requires "+auth.ScopeAdmin)
	case errors.Is(err, app.ErrBulletinNotFound):
		writeProblem(w, http.StatusNotFound, "bulletin not found", err.Error())
	case errors.Is(err, app.ErrBulletinConflict):
		writeProblem(w, http.StatusConflict, "bulletin conflict", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "bulletin register failed", err.Error())
	}
}

// ListBulletins handles GET /psirt/bulletins.
func (h *Handler) ListBulletins(w http.ResponseWriter, r *http.Request) {
	list, err := h.bulletins.List(r.Context())
	if err != nil {
		writeBulletinError(w, err)
		return
	}
	out := make([]gen.Bulletin, 0, len(list))
	for _, b := range list {
		out = append(out, toGenBulletin(b))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateBulletin handles POST /psirt/bulletins.
func (h *Handler) CreateBulletin(w http.ResponseWriter, r *http.Request) {
	var in gen.BulletinInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	editor, actor := bulletinCaller(r.Context())
	b, err := h.bulletins.Create(r.Context(), fromGenBulletinInput(in), editor, actor)
	if err != nil {
		writeBulletinError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toGenBulletin(b))
}

// UpdateBulletin handles PUT /psirt/bulletins/{id}.
func (h *Handler) UpdateBulletin(w http.ResponseWriter, r *http.Request, id string) {
	var in gen.BulletinInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	editor, actor := bulletinCaller(r.Context())
	b, err := h.bulletins.Update(r.Context(), id, fromGenBulletinInput(in), editor, actor)
	if err != nil {
		writeBulletinError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toGenBulletin(b))
}

// RemoveBulletin handles DELETE /psirt/bulletins/{id}.
func (h *Handler) RemoveBulletin(w http.ResponseWriter, r *http.Request, id string) {
	editor, actor := bulletinCaller(r.Context())
	if err := h.bulletins.Remove(r.Context(), id, editor, actor); err != nil {
		writeBulletinError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetBulletinHistory handles GET /psirt/bulletins/{id}/history.
func (h *Handler) GetBulletinHistory(w http.ResponseWriter, r *http.Request, id string) {
	hist, err := h.bulletins.History(r.Context(), id)
	if err != nil {
		writeBulletinError(w, err)
		return
	}
	out := make([]gen.BulletinChange, 0, len(hist))
	for _, c := range hist {
		item := gen.BulletinChange{At: c.At, Actor: c.Actor, Action: c.Action}
		if c.Before != nil {
			b := toGenBulletin(*c.Before)
			item.Before = &b
		}
		if c.After != nil {
			a := toGenBulletin(*c.After)
			item.After = &a
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

// bulletinsByCVE indexes the live register by CVE for the alert rows. The register is the
// team's own and small; an unreadable or unwired one leaves the rows without a bulletin.
func (h *Handler) bulletinsByCVE(ctx context.Context) map[string]gen.BulletinRef {
	list, err := h.bulletins.List(ctx)
	if err != nil {
		return nil
	}
	out := make(map[string]gen.BulletinRef, len(list))
	for _, b := range list {
		if b.CVE != "" {
			out[b.CVE] = gen.BulletinRef{Id: b.ID, BulletinId: b.BulletinID, Title: b.Title, BulletinUrl: b.BulletinURL}
		}
	}
	return out
}
