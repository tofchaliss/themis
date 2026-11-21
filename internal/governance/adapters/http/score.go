package http

import (
	"encoding/json"
	"net/http"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// WithScores attaches the CVSS assessment read (EDR-SCORING-01 S4). Nil ⇒ the route answers 503.
func (h *Handler) WithScores(s *app.ScoreService) *Handler {
	h.scores = s
	return h
}

// GetFindingScore handles GET /findings/{id}/score: the stored roll-up and per-component
// provenance. Nothing is computed here; the numbers come from the stored revisions.
func (h *Handler) GetFindingScore(w http.ResponseWriter, r *http.Request, id gen.FindingId) {
	if h.scores == nil {
		writeProblem(w, http.StatusServiceUnavailable, "score unavailable", "the CVSS assessment is not wired on this node (it needs the Knowledge read seam)")
		return
	}
	v, err := h.scores.Score(r.Context(), domain.FindingID(id))
	if err != nil {
		writeErr(w, "cannot read finding score", err)
		return
	}
	writeJSON(w, http.StatusOK, toFindingScore(v))
}

func toFindingScore(v app.FindingScoreView) gen.FindingScore {
	out := gen.FindingScore{FindingId: v.FindingID, Cve: v.CVE, Components: []gen.ComponentScoreRevision{}, History: []gen.ScoreRevisionSummary{}}
	if r := v.Rollup; r != nil {
		out.Rollup = &gen.FindingScoreRollup{Revision: r.Revision, Cause: r.Cause, RecordedAt: r.RecordedAt, Snapshot: asObject(r.Snapshot)}
	}
	for _, c := range v.Components {
		out.Components = append(out.Components, gen.ComponentScoreRevision{
			Purl: c.PURL, Revision: c.Revision, Cause: c.Cause, RecordedAt: c.RecordedAt, Snapshot: asObject(c.Snapshot),
		})
	}
	for _, s := range v.History {
		out.History = append(out.History, gen.ScoreRevisionSummary{
			Purl: s.PURL, Revision: s.Revision, Cause: s.Cause, ScoreStatus: s.Status, Score: s.Score, RecordedAt: s.RecordedAt,
		})
	}
	return out
}

// asObject renders a snapshot through its own JSON tags, so the wire shape is the stored shape.
func asObject(v any) map[string]interface{} {
	b, _ := json.Marshal(v) // snapshot types hold only JSON-safe fields
	out := map[string]interface{}{}
	_ = json.Unmarshal(b, &out)
	return out
}
