// Package http exposes the Knowledge context's read API over REST, implementing the
// oapi-codegen server interface (package gen) over the read service. Read-only: cards
// evolve via feeds/correlation, not this API. Renders a Problem error envelope.
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/knowledge/adapters/http/gen"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// Handler implements gen.ServerInterface over the Knowledge read service and the feed-health
// service.
type Handler struct {
	read   *app.ReadService
	health *app.FeedHealthService
}

// NewHandler builds a Handler.
func NewHandler(read *app.ReadService, health *app.FeedHealthService) *Handler {
	return &Handler{read: read, health: health}
}

// Router returns an http.Handler serving the Knowledge routes; mount it under the
// OpenAPI base path (/api/v1).
func (h *Handler) Router() http.Handler { return gen.Handler(h) }

// GetFaultlineById handles GET /faultlines/{id}.
func (h *Handler) GetFaultlineById(w http.ResponseWriter, r *http.Request, id string) {
	f, err := h.read.GetByID(r.Context(), domain.FaultlineID(id))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "faultline not found", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "cannot read faultline", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toView(f))
}

// GetFaultlineByCVE handles GET /faultlines?cve=.
func (h *Handler) GetFaultlineByCVE(w http.ResponseWriter, r *http.Request, params gen.GetFaultlineByCVEParams) {
	f, found, err := h.read.GetByCVE(r.Context(), params.Cve)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot read faultline", err.Error())
		return
	}
	if !found {
		writeProblem(w, http.StatusNotFound, "faultline not found", "no card for "+params.Cve)
		return
	}
	writeJSON(w, http.StatusOK, toView(f))
}

// GetFaultlineReleases handles GET /faultlines/{id}/releases.
func (h *Handler) GetFaultlineReleases(w http.ResponseWriter, r *http.Request, id string) {
	rels, err := h.read.AffectedReleases(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot read affected releases", err.Error())
		return
	}
	if rels == nil {
		rels = []string{}
	}
	writeJSON(w, http.StatusOK, rels)
}

// GetFeedHealth handles GET /feeds — the tier-aware feed-health snapshot (B1).
func (h *Handler) GetFeedHealth(w http.ResponseWriter, r *http.Request) {
	rep, err := h.health.Report(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot read feed health", err.Error())
		return
	}
	entries := make([]gen.FeedHealthEntry, 0, len(rep.Feeds))
	for _, e := range rep.Feeds {
		last := e.LastSuccessAt
		entries = append(entries, gen.FeedHealthEntry{
			Source:              strptr(e.Source),
			Tier:                intptr(e.Tier),
			Status:              strptr(e.Status),
			ConsecutiveFailures: intptr(e.ConsecutiveFailures),
			LastSuccessAt:       last,
		})
	}
	stale := rep.SignalsStale
	degraded := rep.DegradedFeeds
	writeJSON(w, http.StatusOK, gen.FeedHealthReport{
		SignalsStale:  &stale,
		Feeds:         &entries,
		DegradedFeeds: &degraded,
	})
}

// --- mappers + helpers -----------------------------------------------------

func toView(f domain.Faultline) gen.FaultlineView {
	v := f.View()
	id, cve, stage := string(f.ID()), f.CVE().String(), string(f.Stage())
	ranges, fixes := v.AffectedRanges, v.FixedVersions
	kev, pub := v.KEV, v.ExploitPublic
	ev := gen.EnterpriseView{
		Severity:       strptr(string(v.Severity)),
		CvssScore:      f32ptr(v.CVSS.Score()),
		CvssVector:     strptr(v.CVSS.Vector()),
		SeveritySource: strptr(v.SeveritySource),
		AffectedRanges: &ranges,
		FixedVersions:  &fixes,
		Epss:           f32ptr(v.EPSS),
		Kev:            &kev,
		ExploitPublic:  &pub,
		Priority:       strptr(v.Priority()),
		Score:          intptr(v.Score()),
	}
	// Omitted when no range evidence contributed — absent reads as "nothing to say", which
	// is exactly right, and keeps a card with no ranges byte-identical on the wire.
	if v.RangeTrust != "" {
		rt := gen.EnterpriseViewRangeTrust(v.RangeTrust)
		ev.RangeTrust = &rt
	}
	apps := make([]gen.Applicability, 0, len(v.Applicabilities))
	for _, a := range v.Applicabilities {
		apps = append(apps, gen.Applicability{Package: strptr(a.Package), Status: strptr(a.Status), Justification: strptr(a.Justification)})
	}
	ev.Applicabilities = &apps
	props := make([]gen.ProposalProvenance, 0, len(f.Proposals()))
	for _, p := range f.Proposals() {
		at := p.ObservedAt()
		props = append(props, gen.ProposalProvenance{
			Source: strptr(p.Source()), Kind: strptr(string(p.Kind())), ObservedAt: &at,
		})
	}
	return gen.FaultlineView{Id: &id, Cve: &cve, Stage: &stage, View: &ev, Proposals: &props}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	writeJSON(w, status, gen.Problem{Title: &title, Detail: &detail})
}

func strptr(s string) *string { return &s }

func f32ptr(f float64) *float32 { v := float32(f); return &v }

func intptr(i int) *int { return &i }
