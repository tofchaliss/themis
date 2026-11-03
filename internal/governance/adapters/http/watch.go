package http

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// The Watch surface (EDR-INCIDENT-01 D2). Reads need any key; creating and growing a Watch needs
// a write-capable key (the router's method floor); deleting one is admin — a Watch holds no truth,
// but it is somebody's working list and a product-scoped key should not be able to drop another
// team's.

// watchNote is the D5 sentence every table carries.
const watchNote = "Fix available is the vendor's statement. Patched is proven only by a new scan or SBOM of this release."

// WithWatches attaches the Watch service behind /watches. Nil ⇒ every /watches route answers 503.
func (h *Handler) WithWatches(w *app.WatchService) *Handler {
	h.watches = w
	return h
}

func (h *Handler) watchesReady(w http.ResponseWriter) bool {
	if h.watches == nil {
		writeProblem(w, http.StatusServiceUnavailable, "watches unavailable", "the Watch service is not wired on this node")
		return false
	}
	return true
}

// watchCreator names who creates a Watch: the authenticated key (its name, else its id) wins
// over anything declared, the declared value stands only on an auth-off node.
func watchCreator(ctx context.Context, declared string) string {
	if p, ok := auth.PrincipalFrom(ctx); ok && p.KeyID != "" {
		if strings.TrimSpace(p.Name) != "" {
			return strings.TrimSpace(p.Name)
		}
		return p.KeyID
	}
	return strings.TrimSpace(declared)
}

// ListWatches handles GET /watches.
func (h *Handler) ListWatches(w http.ResponseWriter, r *http.Request) {
	if !h.watchesReady(w) {
		return
	}
	list, err := h.watches.List(r.Context())
	if err != nil {
		writeErr(w, "cannot list watches", err)
		return
	}
	out := make([]gen.WatchView, 0, len(list))
	for _, wt := range list {
		out = append(out, toWatchView(wt))
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateWatch handles POST /watches.
func (h *Handler) CreateWatch(w http.ResponseWriter, r *http.Request) {
	if !h.watchesReady(w) {
		return
	}
	var body gen.WatchCreate
	if !decode(w, r, &body) {
		return
	}
	creator := watchCreator(r.Context(), derefStr(body.CreatedBy))
	if creator == "" {
		writeProblem(w, http.StatusBadRequest, "invalid watch", "created_by names the person creating the watch and is required when the node runs without auth")
		return
	}
	notify := body.Notify != nil && *body.Notify
	wt, rejected, err := h.watches.Create(r.Context(), body.Name, creator, body.Identifiers, notify)
	switch {
	case errors.Is(err, domain.ErrWatchNameRequired):
		writeProblem(w, http.StatusBadRequest, "invalid watch", err.Error())
		return
	case errors.Is(err, domain.ErrWatchEmpty):
		detail := err.Error()
		if len(rejected) > 0 {
			detail += "; not recognised: " + strings.Join(rejected, ", ")
		}
		writeProblem(w, http.StatusBadRequest, "invalid watch", detail)
		return
	case err != nil:
		writeErr(w, "cannot create watch", err)
		return
	}
	writeJSON(w, http.StatusCreated, gen.WatchCreated{Watch: toWatchView(wt), Added: len(wt.Identifiers()), Rejected: nonNil(rejected)})
}

// GetWatch handles GET /watches/{watchId}.
func (h *Handler) GetWatch(w http.ResponseWriter, r *http.Request, watchID gen.WatchId) {
	if !h.watchesReady(w) {
		return
	}
	wt, err := h.watches.Get(r.Context(), watchID)
	if err != nil {
		writeErr(w, "cannot read watch", err)
		return
	}
	writeJSON(w, http.StatusOK, toWatchView(wt))
}

// DeleteWatch handles DELETE /watches/{watchId}. Admin only.
func (h *Handler) DeleteWatch(w http.ResponseWriter, r *http.Request, watchID gen.WatchId) {
	if p, ok := auth.PrincipalFrom(r.Context()); ok && !p.IsAdmin() {
		writeProblem(w, http.StatusForbidden, "Forbidden", "deleting a watch requires "+auth.ScopeAdmin)
		return
	}
	if !h.watchesReady(w) {
		return
	}
	if err := h.watches.Delete(r.Context(), watchID); err != nil {
		writeErr(w, "cannot delete watch", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AddWatchIdentifiers handles POST /watches/{watchId}/identifiers.
func (h *Handler) AddWatchIdentifiers(w http.ResponseWriter, r *http.Request, watchID gen.WatchId) {
	if !h.watchesReady(w) {
		return
	}
	var body gen.WatchIdentifiersAdd
	if !decode(w, r, &body) {
		return
	}
	wt, added, rejected, err := h.watches.AddIdentifiers(r.Context(), watchID, body.Identifiers)
	if err != nil {
		writeErr(w, "cannot add identifiers", err)
		return
	}
	writeJSON(w, http.StatusOK, gen.WatchCreated{Watch: toWatchView(wt), Added: added, Rejected: nonNil(rejected)})
}

// GetWatchStatus handles GET /watches/{watchId}/status.
func (h *Handler) GetWatchStatus(w http.ResponseWriter, r *http.Request, watchID gen.WatchId) {
	if !h.watchesReady(w) {
		return
	}
	st, err := h.watches.Status(r.Context(), watchID)
	if errors.Is(err, app.ErrWatchUnresolvable) {
		writeProblem(w, http.StatusServiceUnavailable, "watch status unavailable",
			"no Knowledge seam is configured (THEMIS_KNOWLEDGE_URL), so the identifiers cannot be resolved")
		return
	}
	if err != nil {
		writeErr(w, "cannot compute watch status", err)
		return
	}
	out := gen.WatchStatusView{
		Watch: toWatchView(st.Watch), GeneratedAt: st.GeneratedAt, Note: strptr(watchNote),
		Identifiers: make([]gen.WatchIdentifierView, 0, len(st.Identifiers)),
		Rows:        make([]gen.WatchRowView, 0, len(st.Rows)),
		Counts:      map[string]int{},
	}
	for _, is := range st.Identifiers {
		out.Identifiers = append(out.Identifiers, gen.WatchIdentifierView{
			Id: is.ID, Kind: gen.WatchIdentifierViewKind(is.Kind), Cves: nonNil(is.CVEs), Resolved: is.Resolved,
		})
	}
	for _, row := range st.Rows {
		v := gen.WatchRowView{
			Cve: row.CVE, State: gen.WatchRowViewState(row.State),
			Packages: nonNil(row.Packages), Fixes: nonNil(row.Fixes),
			FaultlineId: optStr(row.FaultlineID), FindingId: optStr(string(row.FindingID)),
			ReleaseId: optStr(row.ReleaseID), ProductId: optStr(row.ProductID), ProjectId: optStr(row.ProjectID),
			ProductName: optStr(row.ProductName), ProjectName: optStr(row.ProjectName), Version: optStr(row.Version),
			Stance: optStr(row.Stance), LastEvidenceAt: timeptrIf(row.LastEvidenceAt), LastEvidenceKind: optStr(row.LastEvidenceKind),
		}
		out.Rows = append(out.Rows, v)
	}
	for state, n := range st.Counts {
		out.Counts[string(state)] = n
	}
	writeJSON(w, http.StatusOK, out)
}

func toWatchView(wt domain.Watch) gen.WatchView {
	return gen.WatchView{
		Id: wt.ID(), Name: wt.Name(), CreatedBy: wt.CreatedBy(), CreatedAt: wt.CreatedAt(),
		Identifiers: nonNil(wt.Identifiers()), ResolvedCves: nonNil(wt.ResolvedCVEs()),
		ResolvedAt: timeptrIf(wt.ResolvedAt()), Notify: wt.Notify(),
	}
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
