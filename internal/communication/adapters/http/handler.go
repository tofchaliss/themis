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
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// Handler implements gen.ServerInterface over the Communication write + read services.
type Handler struct {
	write   *app.PublicationService
	read    *app.ReadService
	rollups *app.RollupService // release-scoped VEX rollups (D13); nil = not configured
}

// NewHandler builds a Handler.
func NewHandler(write *app.PublicationService, read *app.ReadService) *Handler {
	return &Handler{write: write, read: read}
}

// WithRollups wires the release-rollup service (D13) and returns the handler for chaining —
// kept out of the constructor so existing call sites keep compiling; production wiring
// always sets it.
func (h *Handler) WithRollups(rs *app.RollupService) *Handler {
	h.rollups = rs
	return h
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
	findingID, releaseID, ok := subjectUnion(w, body.FindingId, body.ReleaseId)
	if !ok {
		return
	}
	// The release-scoped branch (D13.5): the same door, a different materialization — one
	// multi-statement rollup over the whole posture, VEX only.
	if releaseID != "" {
		if h.rollups == nil {
			writeProblem(w, http.StatusNotImplemented, "rollups not configured", "this node has no release-rollup service wired")
			return
		}
		if domain.ArtifactType(body.ArtifactType) != domain.ArtifactVEX {
			writeProblem(w, http.StatusBadRequest, "invalid artifact type", "a release subject supports artifact_type \"vex\" only (D13)")
			return
		}
		id, err := h.rollups.CreateRollup(r.Context(), releaseID, body.Format, deref(body.Audience))
		if err != nil {
			writeRollupErr(w, "cannot create rollup", err)
			return
		}
		idStr := string(id)
		writeJSON(w, http.StatusCreated, gen.CreatePublicationResponse{PublicationId: &idStr})
		return
	}
	id, err := h.write.CreatePublication(r.Context(), findingID, domain.ArtifactType(body.ArtifactType),
		body.Format, deref(body.Audience), deref(body.Channel))
	if err != nil {
		writeErr(w, "cannot create publication", err)
		return
	}
	idStr := string(id)
	writeJSON(w, http.StatusCreated, gen.CreatePublicationResponse{PublicationId: &idStr})
}

// subjectUnion enforces the request's subject rule: EXACTLY one of finding_id / release_id
// (D13.5). Writes the 400 itself so both handlers refuse identically.
func subjectUnion(w http.ResponseWriter, findingID, releaseID *string) (string, string, bool) {
	f, rel := deref(findingID), deref(releaseID)
	if (f == "") == (rel == "") {
		writeProblem(w, http.StatusBadRequest, "invalid subject",
			"supply exactly one of finding_id (a per-Position artifact) or release_id (the release rollup)")
		return "", "", false
	}
	return f, rel, true
}

// writeRollupErr maps rollup-flow errors onto transport statuses: the fail-closed identity
// refusal is a 422 (the release exists, its name chain does not — D13.4), an unsupported
// rollup format a 400 (D13.5), anything else a 500.
func writeRollupErr(w http.ResponseWriter, title string, err error) {
	switch {
	case errors.Is(err, app.ErrIncompleteIdentity):
		writeProblem(w, http.StatusUnprocessableEntity, "release identity unresolved", err.Error())
	case errors.Is(err, serializer.ErrRollupUnsupported), errors.Is(err, serializer.ErrUnknownFormat):
		writeProblem(w, http.StatusBadRequest, "unsupported rollup format", err.Error())
	case errors.Is(err, domain.ErrRollupNotFound):
		writeProblem(w, http.StatusNotFound, "rollup not found", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, title, err.Error())
	}
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
	findingID, releaseID, ok := subjectUnion(w, body.FindingId, body.ReleaseId)
	if !ok {
		return
	}
	if releaseID != "" {
		if h.rollups == nil {
			writeProblem(w, http.StatusNotImplemented, "rollups not configured", "this node has no release-rollup service wired")
			return
		}
		if domain.ArtifactType(body.ArtifactType) != domain.ArtifactVEX {
			writeProblem(w, http.StatusBadRequest, "invalid artifact type", "a release subject supports artifact_type \"vex\" only (D13)")
			return
		}
		payload, err := h.rollups.PreviewRollup(r.Context(), releaseID, body.Format)
		if err != nil {
			writeRollupErr(w, "cannot preview rollup", err)
			return
		}
		sp := string(payload)
		writeJSON(w, http.StatusOK, gen.PreviewResponse{Payload: &sp})
		return
	}
	payload, found, err := h.read.Preview(r.Context(), findingID, domain.ArtifactType(body.ArtifactType), body.Format)
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

// --- release rollups (D13) -----------------------------------------------------------

// ListRollups handles GET /rollups?release= — the full supersession history, newest first.
func (h *Handler) ListRollups(w http.ResponseWriter, r *http.Request, params gen.ListRollupsParams) {
	if h.rollups == nil {
		writeProblem(w, http.StatusNotImplemented, "rollups not configured", "this node has no release-rollup service wired")
		return
	}
	pubs, err := h.rollups.ListRollups(r.Context(), params.Release)
	if err != nil {
		writeRollupErr(w, "cannot list rollups", err)
		return
	}
	out := make([]gen.RollupView, 0, len(pubs))
	for _, p := range pubs {
		out = append(out, toRollupView(p, false)) // list = metadata only; the payload rides the single GET
	}
	writeJSON(w, http.StatusOK, out)
}

// GetRollup handles GET /rollups/{id} — metadata plus the rendered document.
func (h *Handler) GetRollup(w http.ResponseWriter, r *http.Request, id string) {
	if h.rollups == nil {
		writeProblem(w, http.StatusNotImplemented, "rollups not configured", "this node has no release-rollup service wired")
		return
	}
	pub, err := h.rollups.GetRollup(r.Context(), domain.RollupPublicationID(id))
	if err != nil {
		writeRollupErr(w, "cannot read rollup", err)
		return
	}
	writeJSON(w, http.StatusOK, toRollupView(pub, true))
}

// GetRollupStatus handles GET /releases/{id}/rollup-status — the worklist staleness row
// (D13.2): computed drift, surfaced, never auto-acted on.
func (h *Handler) GetRollupStatus(w http.ResponseWriter, r *http.Request, id string, params gen.GetRollupStatusParams) {
	if h.rollups == nil {
		writeProblem(w, http.StatusNotImplemented, "rollups not configured", "this node has no release-rollup service wired")
		return
	}
	format := "openvex"
	if params.Format != nil && *params.Format != "" {
		format = *params.Format
	}
	st, err := h.rollups.Status(r.Context(), id, format, deref(params.Audience))
	if err != nil {
		writeRollupErr(w, "cannot compute rollup status", err)
		return
	}
	found, stale := st.Found, st.Stale
	pid, asOf, stmts, summary := string(st.PublicationID), st.AsOf, st.Statements, st.Summary
	cd, nf, rf, ao := st.Drift.ChangedDecisions, st.Drift.NewFindings, st.Drift.RemovedFindings, st.Drift.AnnotationOnly
	writeJSON(w, http.StatusOK, gen.RollupStatus{
		Found: &found, PublicationId: &pid, AsOf: &asOf, Statements: &stmts,
		Stale: &stale, Summary: &summary,
		Drift: &struct {
			AnnotationOnly   *int `json:"annotation_only,omitempty"`
			ChangedDecisions *int `json:"changed_decisions,omitempty"`
			NewFindings      *int `json:"new_findings,omitempty"`
			RemovedFindings  *int `json:"removed_findings,omitempty"`
		}{AnnotationOnly: &ao, ChangedDecisions: &cd, NewFindings: &nf, RemovedFindings: &rf},
	})
}

func toRollupView(p domain.RollupPublication, includePayload bool) gen.RollupView {
	id, rel, purl := string(p.ID()), p.ReleaseID(), p.ProductPURL()
	format, audience := p.Format(), p.Audience()
	asOf, created := p.AsOf().Format(time.RFC3339), p.CreatedAt().Format(time.RFC3339)
	stmts, withdrawn := p.Statements(), p.WithdrawnExcluded()
	sup, supBy := string(p.Supersedes()), string(p.SupersededBy())
	v := gen.RollupView{
		Id: &id, ReleaseId: &rel, ProductPurl: &purl, Format: &format, Audience: &audience,
		AsOf: &asOf, CreatedAt: &created, Statements: &stmts, WithdrawnExcluded: &withdrawn,
		SupersedesId: &sup, SupersededBy: &supBy,
	}
	if includePayload {
		body := string(p.Payload())
		v.Payload = &body
	}
	return v
}
