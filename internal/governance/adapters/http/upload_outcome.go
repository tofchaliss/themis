package http

import (
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
)

// GetReleaseUploadOutcome serves what the Release's latest new SBOM changed
// (EDR-REMEDIATION-01 D3). 404 when none has been stated; 503 when the reader is not wired.
func (h *Handler) GetReleaseUploadOutcome(w http.ResponseWriter, r *http.Request, releaseID string) {
	rec, found, err := h.read.LatestUploadOutcome(r.Context(), releaseID)
	if errors.Is(err, app.ErrEventFeedUnavailable) {
		writeProblem(w, http.StatusServiceUnavailable, "upload outcome unavailable", err.Error())
		return
	}
	if err != nil {
		writeErr(w, "read upload outcome", err)
		return
	}
	if !found {
		writeProblem(w, http.StatusNotFound, "no upload outcome", "no new SBOM has been evaluated for this release since outcomes were recorded")
		return
	}
	o := rec.Outcome
	out := gen.UploadOutcome{
		SbomId: rec.SBOMID, EvaluatedAt: rec.EvaluatedAt,
		New: o.New, Reappeared: o.Reappeared, NoLongerPresent: o.NoLongerPresent, Unchanged: o.Unchanged,
		NotJudged: o.NotJudged, HasBaseline: o.HasBaseline,
	}
	if len(o.NewCVEs) > 0 {
		out.NewCves = &o.NewCVEs
	}
	if len(o.ReappearedCVEs) > 0 {
		out.ReappearedCves = &o.ReappearedCVEs
	}
	if len(o.GoneCVEs) > 0 {
		out.NoLongerPresentCves = &o.GoneCVEs
	}
	writeJSON(w, http.StatusOK, out)
}
