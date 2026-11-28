package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// The rebuild recommendation of a Release and its approval (EDR-REBUILD-01 step R4). The read
// starts nothing. The approval is the "start rebuild" action of mode ask: it publishes the
// request the recommendation froze, or says why not.

const rebuildApprovalUnwired = "the rebuild approval is not wired on this node"

// WithRebuildApproval attaches the recommendation read and the approval.
func (h *Handler) WithRebuildApproval(s *app.RebuildApprovalService) *Handler {
	h.rebuildApproval = s
	return h
}

// GetReleaseRebuildRecommendation serves the newest recommendation of the Release.
func (h *Handler) GetReleaseRebuildRecommendation(w http.ResponseWriter, r *http.Request, releaseID string) {
	rec, err := h.rebuildApproval.Latest(r.Context(), releaseID)
	switch {
	case errors.Is(err, app.ErrRebuildApprovalUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "rebuild recommendation unavailable", rebuildApprovalUnwired)
	case errors.Is(err, app.ErrRebuildRecommendationNotFound):
		writeProblem(w, http.StatusNotFound, "no rebuild recommendation", "this release has no rebuild recommendation")
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "rebuild recommendation unavailable",
			"the rebuild recommendation could not be read")
	default:
		writeJSON(w, http.StatusOK, toRebuildRecommendation(rec, h.rebuildApproval))
	}
}

func toRebuildRecommendation(rec app.RebuildRecommendation, svc *app.RebuildApprovalService) gen.RebuildRecommendation {
	d := rec.Decision
	now := svc.Now()
	state := rec.State
	// By the clock: a standing recommendation past its time is expired whether or not the
	// sweep has recorded it yet (D44 item 1).
	if state == domain.RebuildRecStanding && domain.RebuildRecommendationExpired(d.DecidedAt, now) {
		state = domain.RebuildRecExpired
	}
	out := gen.RebuildRecommendation{
		Decision: toRebuildDecision(d), State: gen.RebuildRecommendationState(state), StateAt: rec.StateAt,
		ExpiresAt:  d.DecidedAt.Add(domain.RebuildRecommendationTTL),
		CanApprove: state == domain.RebuildRecStanding && d.RecommendReason != domain.RebuildRecommendNoBuildProfile,
	}
	if rec.SupersededBy != "" {
		out.SupersededBy = strptr(rec.SupersededBy)
	}
	if a := rec.Approval; a != nil {
		ga := gen.RebuildApproval{Actor: a.Actor, KeyName: a.KeyName, KeyScopes: a.KeyScopes, ApprovedAt: a.ApprovedAt,
			Tag: a.Tag, TagLevel: a.TagLevel, TagsReadAt: a.TagsReadAt}
		if ga.KeyScopes == nil {
			ga.KeyScopes = []string{}
		}
		ga.PolicyVersions.Installation, ga.PolicyVersions.Product, ga.PolicyVersions.Release =
			a.PolicyVersions.Installation, a.PolicyVersions.Product, a.PolicyVersions.Release
		closed := rec.CycleClosed
		out.Approval, out.CycleClosed = &ga, &closed
	}
	return out
}

// ApproveRebuildRecommendation is the "start rebuild" action (D15, D22, D45, D46).
func (h *Handler) ApproveRebuildRecommendation(w http.ResponseWriter, r *http.Request, decisionID string) {
	var body gen.RebuildApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.ActorId) == "" {
		writeProblem(w, http.StatusBadRequest, "invalid rebuild approval", "actor_id is required: an approval names the person who gives it")
		return
	}
	rec, err := h.rebuildApproval.Recommendation(r.Context(), decisionID)
	if err != nil {
		writeRebuildApprovalError(w, err)
		return
	}
	// Admin, or the key of the Release's own Product (D22). The Product is the one the
	// recommendation froze, so nothing has to be read to decide who may approve.
	if !h.authorizeRebuildOverrideWrite(w, r, domain.RebuildLevelProduct, rec.Decision.ProductID) {
		return
	}
	var key app.RebuildApprovalKey
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		key = app.RebuildApprovalKey{Name: p.Name, Scopes: p.Scopes}
	}
	ans, err := h.rebuildApproval.Approve(r.Context(), decisionID, body.ActorId, key)
	if err != nil {
		writeRebuildApprovalError(w, err)
		return
	}
	out := gen.RebuildApprovalAnswer{
		Result: gen.RebuildApprovalAnswerResult(ans.Result), DecisionId: ans.DecisionID, ReleaseId: ans.ReleaseID,
		State: gen.RebuildApprovalAnswerState(ans.State),
	}
	if ans.StandingID != "" {
		out.StandingDecisionId = strptr(ans.StandingID)
	}
	if ans.EffectiveMode != "" {
		mode := gen.RebuildApprovalAnswerEffectiveMode(ans.EffectiveMode)
		out.EffectiveMode = &mode
	}
	status := http.StatusConflict
	if ans.Result == app.RebuildApprovalApproved {
		status = http.StatusOK
	}
	writeJSON(w, status, out)
}

func writeRebuildApprovalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, app.ErrRebuildApprovalUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "rebuild approval unavailable", rebuildApprovalUnwired)
	case errors.Is(err, app.ErrRebuildRecommendationNotFound):
		writeProblem(w, http.StatusNotFound, "no rebuild recommendation", "no rebuild recommendation has this decision id")
	case errors.Is(err, app.ErrRebuildApprovalActorRequired):
		writeProblem(w, http.StatusBadRequest, "invalid rebuild approval", "actor_id is required: an approval names the person who gives it")
	case errors.Is(err, app.ErrRebuildModeUnread):
		writeProblem(w, http.StatusServiceUnavailable, "rebuild mode unknown",
			"the rebuild mode of this release could not be read, so the approval was refused; the recommendation is unchanged")
	case errors.Is(err, app.ErrRebuildApprovalBusy):
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy changing",
			"the rebuild policy changed during the approval; nothing was written, try again")
	default:
		writeProblem(w, http.StatusInternalServerError, "rebuild approval failed", "the approval could not be recorded")
	}
}
