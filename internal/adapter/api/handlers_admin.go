package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/domain"
)

// TriggerFeedSync forces an on-demand sync of a named intelligence feed, so an
// operator can refresh a feed after fixing its config instead of waiting for the
// next scheduled tick. Admin scope only.
func (h *Handler) TriggerFeedSync(w http.ResponseWriter, r *http.Request) {
	principal, ok := AuthFromContext(r.Context())
	if !ok || !AuthorizeAdmin(principal) {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "admin scope required")
		return
	}
	if h.deps.FeedSyncer == nil {
		WriteCatalogError(w, http.StatusInternalServerError, CodeInternalError)
		return
	}
	feed := chi.URLParam(r, "feed")
	if err := h.deps.FeedSyncer.SyncFeed(r.Context(), feed); err != nil {
		if errors.Is(err, domain.ErrUnknownFeed) {
			WriteProblem(w, r, http.StatusNotFound, "Not Found",
				"unknown feed "+feed+"; available: "+strings.Join(h.deps.FeedSyncer.Feeds(), ", "))
			return
		}
		RespondError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"feed": feed, "synced": true})
}
