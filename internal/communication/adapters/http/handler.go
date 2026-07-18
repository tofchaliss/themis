// Package http exposes the Communication context's publish-trigger + read/preview API over
// REST, implementing the oapi-codegen server interface (package gen) over the app services.
// Publication is human-triggered (D4); reads serve recorded Publications (payload regenerated
// if pruned), the publishable-positions worklist, and a non-recording preview. Renders a
// Problem error envelope.
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/communication/adapters/http/gen"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// Handler implements gen.ServerInterface over the Communication write + read services.
type Handler struct {
	write *app.PublicationService
	read  *app.ReadService
}

// NewHandler builds a Handler.
func NewHandler(write *app.PublicationService, read *app.ReadService) *Handler {
	return &Handler{write: write, read: read}
}

// Router returns an http.Handler serving the Communication routes; mount it under the
// OpenAPI base path (/api/v1).
func (h *Handler) Router() http.Handler { return gen.Handler(h) }

// CreatePublication handles POST /publications — the human publish trigger (D4).
func (h *Handler) CreatePublication(w http.ResponseWriter, r *http.Request) {
	var body gen.CreatePublicationRequest
	if !decode(w, r, &body) {
		return
	}
	if !domain.ArtifactType(body.ArtifactType).Valid() {
		writeProblem(w, http.StatusBadRequest, "invalid artifact type", "unknown artifact type "+body.ArtifactType)
		return
	}
	id, err := h.write.CreatePublication(r.Context(), body.FindingId, domain.ArtifactType(body.ArtifactType),
		body.Format, deref(body.Audience), deref(body.Channel))
	if err != nil {
		writeErr(w, "cannot create publication", err)
		return
	}
	idStr := string(id)
	writeJSON(w, http.StatusCreated, gen.CreatePublicationResponse{PublicationId: &idStr})
}

// GetPublication handles GET /publications/{id}.
func (h *Handler) GetPublication(w http.ResponseWriter, r *http.Request, id string) {
	pub, payload, err := h.read.GetPublication(r.Context(), domain.PublicationID(id))
	if err != nil {
		writeErr(w, "cannot read publication", err)
		return
	}
	writeJSON(w, http.StatusOK, toPublicationView(pub, payload))
}

// ListPublications handles GET /publications?release=.
func (h *Handler) ListPublications(w http.ResponseWriter, r *http.Request, params gen.ListPublicationsParams) {
	pubs, err := h.read.ListByRelease(r.Context(), params.Release)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot list publications", err.Error())
		return
	}
	out := make([]gen.PublicationView, 0, len(pubs))
	for _, p := range pubs {
		out = append(out, toPublicationView(p, nil)) // list omits payload bytes
	}
	writeJSON(w, http.StatusOK, out)
}

// PreviewPublication handles POST /previews — a non-recording render (D10).
func (h *Handler) PreviewPublication(w http.ResponseWriter, r *http.Request) {
	var body gen.PreviewRequest
	if !decode(w, r, &body) {
		return
	}
	if !domain.ArtifactType(body.ArtifactType).Valid() {
		writeProblem(w, http.StatusBadRequest, "invalid artifact type", "unknown artifact type "+body.ArtifactType)
		return
	}
	payload, found, err := h.read.Preview(r.Context(), body.FindingId, domain.ArtifactType(body.ArtifactType), body.Format)
	if err != nil {
		writeErr(w, "cannot preview", err)
		return
	}
	if !found {
		writeProblem(w, http.StatusNotFound, "position not found", "no current position for that finding")
		return
	}
	s := string(payload)
	writeJSON(w, http.StatusOK, gen.PreviewResponse{Payload: &s})
}

// GetPublishableQueue handles GET /publishable-positions.
func (h *Handler) GetPublishableQueue(w http.ResponseWriter, r *http.Request) {
	entries, err := h.read.PublishableQueue(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot read publishable positions", err.Error())
		return
	}
	out := make([]gen.QueueEntryView, 0, len(entries))
	for _, e := range entries {
		out = append(out, toQueueEntryView(e))
	}
	writeJSON(w, http.StatusOK, out)
}

// --- mappers + helpers ---------------------------------------------------------------

func toPublicationView(p domain.Publication, payload []byte) gen.PublicationView {
	art := p.Artifact()
	l := p.Lineage()
	id, typ, stance, format, audience, channel := string(p.ID()), string(p.Type()), string(p.Stance()), p.Format(), p.Audience(), p.Channel()
	pv, delivery, superseded := art.PositionVersion, string(p.Delivery().Status), p.IsSuperseded()
	rel, fnd, fl, cve := l.ReleaseID, l.FindingID, l.FaultlineID, l.CVE
	view := gen.PublicationView{
		Id: &id, ArtifactType: &typ, Stance: &stance, Format: &format, Audience: &audience, Channel: &channel,
		PositionVersion: &pv, ReleaseId: &rel, FindingId: &fnd, FaultlineId: &fl, Cve: &cve,
		DeliveryStatus: &delivery, Superseded: &superseded,
	}
	if payload != nil {
		s := string(payload)
		view.Payload = &s
	}
	return view
}

func toQueueEntryView(e app.QueueEntry) gen.QueueEntryView {
	fnd, rel, fl, cve, stance := e.FindingID, e.ReleaseID, e.FaultlineID, e.CVE, string(e.Stance)
	ver, stale := e.Version, e.Stale
	return gen.QueueEntryView{
		FindingId: &fnd, ReleaseId: &rel, FaultlineId: &fl, Cve: &cve, Version: &ver, Stance: &stance, Stale: &stale,
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return false
	}
	return true
}

// writeErr maps a service error to the Problem envelope with the right status.
func writeErr(w http.ResponseWriter, title string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, app.ErrPositionNotFound):
		writeProblem(w, http.StatusNotFound, title, err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, title, err.Error())
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	writeJSON(w, status, gen.Problem{Title: &title, Detail: &detail})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
