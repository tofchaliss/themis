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
	gather *app.GatherService // nil / sourceless ⇒ POST /faultlines/gather refuses honestly
	// scanner serves the on-demand unresolved-components query (EDR-IDENTITY-01 D6). nil ⇒ the
	// endpoint refuses honestly rather than answering "none", which would read as "all clear".
	scanner *app.ScannerReportService
}

// NewHandler builds a Handler.
func NewHandler(read *app.ReadService, health *app.FeedHealthService) *Handler {
	return &Handler{read: read, health: health}
}

// WithGather wires the on-demand per-CVE gather (G-AI-1) and returns the handler for chaining.
func (h *Handler) WithGather(g *app.GatherService) *Handler {
	h.gather = g
	return h
}

// WithScanner wires the scanner-report service for the unresolved-components query (D6) and
// returns the handler for chaining.
func (h *Handler) WithScanner(s *app.ScannerReportService) *Handler {
	h.scanner = s
	return h
}

// Router returns an http.Handler serving the Knowledge routes; mount it under the
// OpenAPI base path (/api/v1).
func (h *Handler) Router() http.Handler { return gen.Handler(h) }

// GatherCVE handles POST /faultlines/gather — the on-demand, operator-triggered per-CVE fetch
// (G-AI-1). Gathering Is Not Knowing: everything folds as ordinary source Proposals.
func (h *Handler) GatherCVE(w http.ResponseWriter, r *http.Request) {
	if !h.gather.Enabled() {
		writeProblem(w, http.StatusServiceUnavailable, "no gather source wired",
			"this node has no per-CVE source configured for on-demand gathering")
		return
	}
	var req gen.GatherCVEJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	res, err := h.gather.GatherCVE(r.Context(), req.Cve)
	if err != nil {
		if errors.Is(err, app.ErrInvalidCVE) {
			writeProblem(w, http.StatusBadRequest, "invalid cve", err.Error())
			return
		}
		writeProblem(w, http.StatusInternalServerError, "gather failed", err.Error())
		return
	}
	type sourceOut struct {
		Source    string `json:"source"`
		Found     bool   `json:"found"`
		Recorded  bool   `json:"recorded"`
		Withdrawn bool   `json:"withdrawn"`
		Error     string `json:"error,omitempty"`
	}
	out := struct {
		CVE         string      `json:"cve"`
		FaultlineID string      `json:"faultline_id,omitempty"`
		Sources     []sourceOut `json:"sources"`
	}{CVE: res.CVE, FaultlineID: res.FaultlineID, Sources: make([]sourceOut, 0, len(res.Sources))}
	for _, sg := range res.Sources {
		out.Sources = append(out.Sources, sourceOut{
			Source: sg.Source, Found: sg.Found, Recorded: sg.Recorded, Withdrawn: sg.Withdrawn, Error: sg.Err,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

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
	carriers := v.CarrierProducts
	kev, pub := v.KEV, v.ExploitPublic
	ev := gen.EnterpriseView{
		Severity:       strptr(string(v.Severity)),
		CvssScore:      f32ptr(v.CVSS.Score()),
		CvssVector:     strptr(v.CVSS.Vector()),
		SeveritySource: strptr(v.SeveritySource),
		Summary:        strptr(v.Summary),
		SummarySource:  strptr(v.SummarySource),
		AffectedRanges: &ranges,
		FixedVersions:  &fixes,
		Fixes:          fixesOut(v.Fixes),
		Epss:           f32ptr(v.EPSS),
		Kev:            &kev,
		ExploitPublic:  &pub,
		Priority:       strptr(v.Priority()),
		Score:          intptr(v.Score()),
		// The carrier side of the correlation (EDR-ATTRIBUTION-01 D10). Knowledge has always
		// held it and used it to classify claims; it never left the context, so a consumer
		// could see that NO component matched a carrier but could not say WHICH carrier went
		// unmatched. Emitting it costs nothing and is the difference between "attribution gap"
		// as a label and as a statement a reviewer can act on.
		CarrierProducts: &carriers,
	}
	// Omitted when no range evidence contributed — absent reads as "nothing to say", which
	// is exactly right, and keeps a card with no ranges byte-identical on the wire.
	if v.RangeTrust != "" {
		rt := gen.EnterpriseViewRangeTrust(v.RangeTrust)
		ev.RangeTrust = &rt
	}
	apps := make([]gen.Applicability, 0, len(v.Applicabilities))
	for _, a := range v.Applicabilities {
		a := a
		app0 := gen.Applicability{Package: strptr(a.Package), Status: strptr(a.Status), Justification: strptr(a.Justification)}
		// The vendor-stated scope (EDR-VEX-02 D5). Emitted as two flat fields so a consumer
		// cannot mistake a partially-populated object for an established scope: both empty means
		// the vendor supplied no readable scope, which reads as applicability `unknown`.
		if a.Scope.Family != "" {
			app0.ScopeFamily = strptr(a.Scope.Family)
		}
		if a.Scope.Major != "" {
			app0.ScopeMajor = strptr(a.Scope.Major)
		}
		apps = append(apps, app0)
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

// fixesOut renders the package-attributed fixes. Omitted when empty so a card with nothing to
// say is byte-identical on the wire to one written before the field existed.
func fixesOut(fixes []domain.FixedVersion) *[]gen.FixedVersion {
	if len(fixes) == 0 {
		return nil
	}
	out := make([]gen.FixedVersion, 0, len(fixes))
	for _, f := range fixes {
		pkg, ver := f.Package, f.Version
		fv := gen.FixedVersion{Package: &pkg, Version: &ver}
		// Omitted when unknown, so a card whose sources never said stays byte-identical on the
		// wire — and so a consumer can tell "generic" apart from "not stated" (KN-FIX-3).
		if f.Ecosystem != "" {
			eco := f.Ecosystem
			fv.Ecosystem = &eco
		}
		out = append(out, fv)
	}
	return &out
}

// GetUnresolvedComponents answers "which components did this scanner report NAME but not
// IDENTIFY?" (EDR-IDENTITY-01 D6).
//
// Recomputed on demand from immutable evidence rather than read from a stored count, so the
// answer cannot drift from the behaviour it describes — see app.UnresolvedComponents. The
// endpoint exists because a correct answer nobody can see is indistinguishable from a wrong one,
// and these observations are neither findings nor bystanders: they are evidence Themis holds and
// cannot yet identify.
func (h *Handler) GetUnresolvedComponents(w http.ResponseWriter, r *http.Request, evidenceId string) {
	if h.scanner == nil {
		writeProblem(w, http.StatusInternalServerError, "scanner ingestion not wired",
			"this node cannot resolve component identity")
		return
	}
	rep, err := h.scanner.UnresolvedComponents(r.Context(), evidenceId)
	switch {
	case errors.Is(err, app.ErrNoSuchEvidence):
		writeProblem(w, http.StatusNotFound, "no such evidence", evidenceId)
		return
	case errors.Is(err, app.ErrNotScannerReport):
		writeProblem(w, http.StatusConflict, "not a scanner report",
			"only a scanner report carries observations to resolve")
		return
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "cannot compute unresolved components", err.Error())
		return
	}
	comps := make([]gen.UnresolvedComponent, 0, len(rep.Unresolved))
	for _, u := range rep.Unresolved {
		c := gen.UnresolvedComponent{
			Name:    u.Name,
			Version: u.Version,
			Reason:  gen.UnresolvedComponentReason(u.Reason),
		}
		if u.Ecosystem != "" {
			c.Ecosystem = strptr(u.Ecosystem)
		}
		if u.Origin != "" {
			c.Origin = strptr(u.Origin)
		}
		// Verbatim and unmodified — never synthesized (D3). Empty when the report offered none,
		// which is a different observation from offering something unusable.
		if u.RawPURL != "" {
			c.ObservedPurl = strptr(u.RawPURL)
		}
		comps = append(comps, c)
	}
	writeJSON(w, http.StatusOK, gen.UnresolvedComponentsReport{
		EvidenceId: rep.EvidenceID,
		ReleaseId:  rep.ReleaseID,
		Resolved:   rep.Resolved,
		Unresolved: len(rep.Unresolved),
		Components: comps,
	})
}
