package http

import (
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// Owner-set severity (EDR-SCORING-01 section 7.1). Reading and the preview need the read scope;
// setting and removing are admin only (OS4), like the SLA policy: a severity sets the priority
// and the deadline of every Finding it is applied to.

// WithSeverity attaches the owner-set severity service. Nil ⇒ the routes answer 503.
func (h *Handler) WithSeverity(s *app.SeverityService) *Handler {
	h.severity = s
	return h
}

func (h *Handler) severityReady(w http.ResponseWriter) bool {
	if h.severity == nil {
		writeProblem(w, http.StatusServiceUnavailable, "severity unavailable", "the owner-set severity service is not wired on this node")
		return false
	}
	return true
}

// severityAdmin refuses a caller that is not an admin. No principal means auth is disabled.
func severityAdmin(w http.ResponseWriter, r *http.Request) bool {
	if p, ok := auth.PrincipalFrom(r.Context()); ok && !p.IsAdmin() {
		writeProblem(w, http.StatusForbidden, "Forbidden", "setting or removing a severity requires "+auth.ScopeAdmin)
		return false
	}
	return true
}

func severityActor(w http.ResponseWriter, r *http.Request, declared string) (domain.Actor, bool) {
	id, ok := actorProvenance(r.Context(), declared)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid actor", "actor_id is required when authentication is disabled")
		return domain.Actor{}, false
	}
	return domain.Actor{Kind: domain.ActorHuman, ID: id}, true
}

// writeSeverityErr maps the severity errors a person can fix to 400 / 404 / 503.
func writeSeverityErr(w http.ResponseWriter, title string, err error) {
	switch {
	case errors.Is(err, domain.ErrOwnerSeverityInput), errors.Is(err, domain.ErrOwnerSeverityLevel),
		errors.Is(err, domain.ErrOwnerSeverityVector), errors.Is(err, domain.ErrOwnerSeverityReason),
		errors.Is(err, domain.ErrOwnerSeverityActor), errors.Is(err, app.ErrSeverityTargetInvalid):
		writeProblem(w, http.StatusBadRequest, title, err.Error())
	case errors.Is(err, app.ErrNothingToReview):
		writeProblem(w, http.StatusConflict, title, err.Error())
	case errors.Is(err, app.ErrNoOwnerSeverity):
		writeProblem(w, http.StatusNotFound, title, err.Error())
	case errors.Is(err, app.ErrSeverityTargetsUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, title,
			"no Registry seam is configured (THEMIS_REGISTRY_URL), so the releases of the product cannot be listed")
	default:
		writeErr(w, title, err)
	}
}

// GetFindingSeverity handles GET /findings/{id}/severity.
func (h *Handler) GetFindingSeverity(w http.ResponseWriter, r *http.Request, id gen.FindingId) {
	if !h.severityReady(w) {
		return
	}
	h.writeSeverityView(w, r, id)
}

func (h *Handler) writeSeverityView(w http.ResponseWriter, r *http.Request, id string) {
	v, err := h.severity.View(r.Context(), domain.FindingID(id))
	if err != nil {
		writeSeverityErr(w, "cannot read severity", err)
		return
	}
	writeJSON(w, http.StatusOK, toFindingSeverity(v))
}

// SetFindingSeverity handles PUT /findings/{id}/severity. Admin only.
func (h *Handler) SetFindingSeverity(w http.ResponseWriter, r *http.Request, id gen.FindingId) {
	if !severityAdmin(w, r) || !h.severityReady(w) {
		return
	}
	var body gen.SetSeverityRequest
	if !decode(w, r, &body) {
		return
	}
	actor, ok := severityActor(w, r, body.ActorId)
	if !ok {
		return
	}
	in := app.SetSeverityInput{Reason: body.Reason, Actor: actor}
	if body.Level != nil {
		in.Level = *body.Level
	}
	if body.Vector != nil {
		in.Vector = *body.Vector
	}
	if body.ApplyTo != nil {
		for _, t := range *body.ApplyTo {
			in.ApplyTo = append(in.ApplyTo, domain.FindingID(t))
		}
	}
	res, err := h.severity.Set(r.Context(), domain.FindingID(id), in)
	if err != nil {
		writeSeverityErr(w, "cannot set severity", err)
		return
	}
	v, err := h.severity.View(r.Context(), domain.FindingID(id))
	if err != nil {
		writeSeverityErr(w, "cannot read severity", err)
		return
	}
	writeJSON(w, http.StatusOK, gen.SetSeverityResult{Applied: res.Applied, Replaced: res.Replaced, Severity: toFindingSeverity(v)})
}

// RemoveFindingSeverity handles POST /findings/{id}/severity/remove. Admin only.
func (h *Handler) RemoveFindingSeverity(w http.ResponseWriter, r *http.Request, id gen.FindingId) {
	if !severityAdmin(w, r) || !h.severityReady(w) {
		return
	}
	var body gen.RemoveFindingSeverityJSONRequestBody
	if !decode(w, r, &body) {
		return
	}
	actor, ok := severityActor(w, r, body.ActorId)
	if !ok {
		return
	}
	if err := h.severity.Remove(r.Context(), domain.FindingID(id), actor); err != nil {
		writeSeverityErr(w, "cannot remove severity", err)
		return
	}
	h.writeSeverityView(w, r, id)
}

// KeepFindingSeverity handles POST /findings/{id}/severity/keep. Admin only.
func (h *Handler) KeepFindingSeverity(w http.ResponseWriter, r *http.Request, id gen.FindingId) {
	if !severityAdmin(w, r) || !h.severityReady(w) {
		return
	}
	var body gen.KeepFindingSeverityJSONRequestBody
	if !decode(w, r, &body) {
		return
	}
	actor, ok := severityActor(w, r, body.ActorId)
	if !ok {
		return
	}
	if err := h.severity.Keep(r.Context(), domain.FindingID(id), actor); err != nil {
		writeSeverityErr(w, "cannot keep severity", err)
		return
	}
	h.writeSeverityView(w, r, id)
}

// PreviewFindingSeverity handles POST /findings/{id}/severity/preview. It records nothing.
func (h *Handler) PreviewFindingSeverity(w http.ResponseWriter, r *http.Request, id gen.FindingId) {
	if !h.severityReady(w) {
		return
	}
	var body gen.PreviewFindingSeverityJSONRequestBody
	if !decode(w, r, &body) {
		return
	}
	level, vector := "", ""
	if body.Level != nil {
		level = *body.Level
	}
	if body.Vector != nil {
		vector = *body.Vector
	}
	o, err := h.severity.Preview(r.Context(), domain.FindingID(id), level, vector)
	if err != nil {
		writeSeverityErr(w, "cannot preview severity", err)
		return
	}
	out := gen.SeverityPreview{Kind: gen.SeverityPreviewKind(o.Kind), Level: string(o.Level), Score: o.Score, OriginalScore: o.OriginalScore}
	if o.Vector != "" {
		out.Vector = strptr(o.Vector)
	}
	writeJSON(w, http.StatusOK, out)
}

// GetFindingSeverityTargets handles GET /findings/{id}/severity/targets: the pick list.
func (h *Handler) GetFindingSeverityTargets(w http.ResponseWriter, r *http.Request, id gen.FindingId) {
	if !h.severityReady(w) {
		return
	}
	targets, err := h.severity.Targets(r.Context(), domain.FindingID(id))
	if err != nil {
		writeSeverityErr(w, "cannot list severity targets", err)
		return
	}
	out := gen.SeverityTargets{FindingId: id, Count: len(targets), Targets: []gen.SeverityTarget{}}
	for _, t := range targets {
		row := gen.SeverityTarget{
			FindingId: string(t.FindingID), ReleaseId: t.ReleaseID,
			ProductId: strptr(t.ProductID), ProjectId: strptr(t.ProjectID),
			ProductName: strptr(t.ProductName), ProjectName: strptr(t.ProjectName), Version: strptr(t.Version),
		}
		if t.Owner != nil {
			o := toOwnerSeverity(*t.Owner)
			row.Owner = &o
			out.WithOwnerSeverity++
		}
		out.Targets = append(out.Targets, row)
	}
	writeJSON(w, http.StatusOK, out)
}

func toFindingSeverity(v app.SeverityView) gen.FindingSeverity {
	out := gen.FindingSeverity{FindingId: string(v.FindingID), Cve: v.CVE, History: []gen.OwnerSeverity{}}
	if s := v.Original.Score; s != nil {
		score := *s
		out.OriginalScore, out.OriginalSeverity = &score, strptr(domain.ScoreBand(score))
	}
	if v.Original.Vector != "" {
		out.OriginalVector = strptr(v.Original.Vector)
	}
	if v.Owner != nil {
		o := toOwnerSeverity(*v.Owner)
		if v.Review != "" {
			o.ReviewReason = strptr(v.Review)
		}
		out.Owner = &o
	}
	for _, rec := range v.History {
		o := toOwnerSeverity(rec.OwnerSeverity)
		if !rec.EndedAt.IsZero() {
			at, cause := rec.EndedAt, gen.OwnerSeverityEndCause(rec.EndCause)
			o.EndedAt, o.EndedBy, o.EndCause = &at, strptr(rec.EndedBy), &cause
		}
		out.History = append(out.History, o)
	}
	return out
}

func toOwnerSeverity(o domain.OwnerSeverity) gen.OwnerSeverity {
	out := gen.OwnerSeverity{
		Kind: gen.OwnerSeverityKind(o.Kind), Level: gen.OwnerSeverityLevel(o.Level), Score: o.Score,
		OriginalScore: o.OriginalScore, Reason: o.Reason, SetBy: o.Actor.ID, SetAt: o.SetAt,
	}
	if o.Vector != "" {
		out.Vector = strptr(o.Vector)
	}
	if o.PickedFrom != "" {
		out.PickedFrom = strptr(string(o.PickedFrom))
	}
	if o.OriginalVector != "" {
		out.OriginalVector = strptr(o.OriginalVector)
	}
	if o.Kept != nil {
		at := o.Kept.At
		out.KeptAt, out.KeptBy = &at, strptr(o.Kept.By)
	}
	return out
}
