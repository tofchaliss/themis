package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/themis-project/themis/internal/knowledge/adapters/http/gen"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// WithRatings wires the source-rating read (EDR-SCORING-01 S2).
func (h *Handler) WithRatings(r *app.RatingService) *Handler {
	h.ratings = r
	return h
}

// GetFaultlineRatings handles GET /faultlines/{id}/ratings.
func (h *Handler) GetFaultlineRatings(w http.ResponseWriter, r *http.Request, id string) {
	if h.ratings == nil {
		writeProblem(w, http.StatusServiceUnavailable, "no rating store wired", "this node records no source ratings")
		return
	}
	f, err := h.read.GetByID(r.Context(), domain.FaultlineID(id))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "faultline not found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "cannot read faultline", err.Error())
		return
	}
	view, err := h.ratings.RatingsForCVE(r.Context(), f.CVE().String())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot read source ratings", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toRatings(view))
}

func toRatings(v app.RatingsView) gen.SourceRatings {
	out := gen.SourceRatings{Cve: v.CVE, Observations: []gen.SourceObservation{}, Ratings: []gen.SourceRating{}}
	for _, o := range v.Observations {
		out.Observations = append(out.Observations, gen.SourceObservation{
			Id: o.ID, Source: o.Source, Feed: o.Feed, DocumentRef: o.DocumentRef, Revision: optString(o.Revision),
			Fingerprint: optString(o.Fingerprint),
			UpdatedAt:   toSourceTime(o.UpdatedAt), Complete: o.Complete, Applicability: optStrings(o.Applicability),
			SeverityWord: optString(o.SeverityWord), FirstObservedAt: o.FirstObservedAt,
		})
	}
	for _, rv := range v.Ratings {
		r := rv.Rating
		g := gen.SourceRating{
			Id: r.ID, ObservationId: r.ObservationID, Source: r.Source, Feed: r.Feed, Assessor: r.Assessor,
			AssessorKey: optString(domain.NormaliseAssessor(r.Assessor)),
			Publisher:   optString(r.Publisher), NvdType: optString(r.NVDType), CvssVersion: r.Version, Vector: r.Vector,
			SeverityWord: optString(r.SeverityWord), AssertedContext: optString(r.AssertedContext),
			InheritedContext: optString(r.InheritedContext), EffectiveContext: optString(r.EffectiveContext()),
			RecordedAt: r.RecordedAt, Status: gen.SourceRatingStatus(rv.Status),
		}
		if r.HasStatedScore {
			g.StatedScore = optScore(r.StatedScore)
		}
		if e := rv.Event; e != nil {
			g.StatusEvent = &gen.SourceRatingEvent{
				Kind: gen.SourceRatingEventKind(e.Kind), CausedBy: e.CausedBy, ReplacedBy: optString(e.ReplacedBy),
				SourceTime: toSourceTime(e.SourceTime), LearnedAt: e.LearnedAt,
			}
		}
		if val := rv.Validation; val != nil {
			gv := &gen.RatingValidation{
				CalculatorVersion: val.CalculatorVersion, SpecVersion: optString(val.SpecVersion),
				Result: gen.RatingValidationResult(val.Result), Reason: optString(val.Reason), ValidatedAt: optTime(val.ValidatedAt),
			}
			if val.Result == domain.ValidationValid {
				gv.BaseScore = optScore(val.Base)
			}
			if val.HasTemporal {
				gv.TemporalScore = optScore(val.Temporal)
			}
			if val.Stated != "" {
				s := gen.RatingValidationStatedComparison(val.Stated)
				gv.StatedComparison = &s
			}
			g.Validation = gv
		}
		if rv.Identity.IdentityKey != "" {
			linked, amb := rv.Identity.Linked, rv.Identity.Ambiguous
			g.Identity = &gen.AssessmentIdentity{Key: rv.Identity.IdentityKey, Linked: &linked, AmbiguousLink: &amb}
		}
		out.Ratings = append(out.Ratings, g)
	}
	return out
}

func toSourceTime(t domain.SourceTime) *gen.SourceTime {
	if t.Original == "" {
		return nil
	}
	out := &gen.SourceTime{Original: optString(t.Original), Instant: optTime(t.Instant)}
	if t.Interpretation != "" {
		i := gen.SourceTimeInterpretation(t.Interpretation)
		out.Interpretation = &i
	}
	return out
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optStrings(s []string) *[]string {
	if len(s) == 0 {
		return nil
	}
	return &s
}

func optScore(v float64) *float32 {
	f := float32(v)
	return &f
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
