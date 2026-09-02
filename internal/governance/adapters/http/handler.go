// Package http exposes the Governance context's triage + read API over REST, implementing
// the oapi-codegen server interface (package gen) over the app services. Writes drive the
// governed decision workflow (raise / accept / reject a proposal, lifecycle transitions);
// reads serve Findings, Positions, and the release-posture / blast-radius rollups. Renders
// a Problem error envelope. The deciding actor arrives via the request (the authorization
// hook seam) — a real deployment derives it from auth middleware; the ADR-fixed rule
// (only a human or a Governance-owned policy may decide) is enforced in the app (D11).
package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Handler implements gen.ServerInterface over the Governance write + read services.
type Handler struct {
	write *app.FindingService
	read  *app.ReadService
}

// NewHandler builds a Handler.
func NewHandler(write *app.FindingService, read *app.ReadService) *Handler {
	return &Handler{write: write, read: read}
}

// Router returns an http.Handler serving the Governance routes; mount it under the OpenAPI
// base path (/api/v1).
func (h *Handler) Router() http.Handler { return gen.Handler(h) }

// --- reads ---------------------------------------------------------------------------

// GetFinding handles GET /findings/{id}.
func (h *Handler) GetFinding(w http.ResponseWriter, r *http.Request, id string) {
	f, err := h.read.GetFinding(r.Context(), domain.FindingID(id))
	if err != nil {
		writeErr(w, "cannot read finding", err)
		return
	}
	writeJSON(w, http.StatusOK, toFindingView(f))
}

// GetFindingAssessment handles GET /findings/{id}/assessment — the FindingAssessment Domain
// Projection (EDR-TRUST-01 T10).
func (h *Handler) GetFindingAssessment(w http.ResponseWriter, r *http.Request, id string) {
	a, err := h.read.GetFindingAssessment(r.Context(), domain.FindingID(id))
	if err != nil {
		writeErr(w, "cannot read finding assessment", err)
		return
	}
	writeJSON(w, http.StatusOK, toFindingAssessment(a))
}

// toFindingAssessment maps the projection onto the wire. The knowledge half is omitted when
// it is absent, so a consumer can tell "Knowledge was unreachable" from "the CVE has no
// enrichment" — collapsing both into zero values would hide an outage.
func toFindingAssessment(a app.FindingAssessment) gen.FindingAssessment {
	view := toFindingView(a.Finding)
	out := gen.FindingAssessment{Finding: &view}
	k := a.Knowledge
	if k.FaultlineID == "" {
		return out
	}
	ranges, fixes := k.AffectedRanges, k.FixedVersions
	kev, pub := k.KEV, k.ExploitPublic
	cvss, epss := float32(k.CVSSScore), float32(k.EPSS)
	kn := gen.FaultlineKnowledge{
		FaultlineId: strptr(k.FaultlineID), Cve: strptr(k.CVE), Severity: strptr(k.Severity),
		Summary:   strptr(k.Summary),
		CvssScore: &cvss, Epss: &epss, Kev: &kev, ExploitPublic: &pub,
		AffectedRanges: &ranges, FixedVersions: &fixes,
	}
	// The package-attributed selection and the count of what could not be attributed
	// (AI-GROUND-1). Both ride out so a consumer can distinguish "no fix published" from
	// "fixes exist but none of them is yours".
	attributed := make([]struct {
		Package *string `json:"package,omitempty"`
		Version *string `json:"version,omitempty"`
	}, 0, len(k.Fixes))
	for _, f := range k.Fixes {
		pkg, ver := f.Package, f.Version
		attributed = append(attributed, struct {
			Package *string `json:"package,omitempty"`
			Version *string `json:"version,omitempty"`
		}{Package: &pkg, Version: &ver})
	}
	unattributed := k.UnattributedFixes
	kn.Fixes, kn.UnattributedFixes = &attributed, &unattributed
	if k.RangeTrust != "" {
		rt := gen.FaultlineKnowledgeRangeTrust(k.RangeTrust)
		kn.RangeTrust = &rt
	}
	out.Knowledge = &kn
	return out
}

// GetFindingByKey handles GET /findings?release=&faultline=.
func (h *Handler) GetFindingByKey(w http.ResponseWriter, r *http.Request, params gen.GetFindingByKeyParams) {
	f, found, err := h.read.GetFindingByKey(r.Context(), params.Release, params.Faultline)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot read finding", err.Error())
		return
	}
	if !found {
		writeProblem(w, http.StatusNotFound, "finding not found", "no finding for that (release, faultline)")
		return
	}
	writeJSON(w, http.StatusOK, toFindingView(f))
}

// GetPosition handles GET /findings/{id}/position?version=.
func (h *Handler) GetPosition(w http.ResponseWriter, r *http.Request, id string, params gen.GetPositionParams) {
	version := 0
	if params.Version != nil {
		version = *params.Version
	}
	pos, ok, err := h.read.GetPosition(r.Context(), domain.FindingID(id), version)
	if err != nil {
		writeErr(w, "cannot read position", err)
		return
	}
	if !ok {
		writeProblem(w, http.StatusNotFound, "position not found", "no such Enterprise Position")
		return
	}
	writeJSON(w, http.StatusOK, toPositionView(pos))
}

// GetReleasePosture handles GET /releases/{releaseId}/posture.
func (h *Handler) GetReleasePosture(w http.ResponseWriter, r *http.Request, releaseID string) {
	entries, err := h.read.ReleasePosture(r.Context(), releaseID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot read release posture", err.Error())
		return
	}
	out := make([]gen.PostureEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, toPostureEntry(e))
	}
	writeJSON(w, http.StatusOK, out)
}

// CompareReleases handles GET /releases/{releaseId}/compare/{candidateId} — the
// cross-release posture diff (D16). The honesty guard maps to explicit statuses: 422 when a
// side has no evidence (absence proves nothing yet), 502 when Evidence cannot be asked —
// never a silent empty diff, which would read as "everything fixed".
func (h *Handler) CompareReleases(w http.ResponseWriter, r *http.Request, releaseID, candidateID string) {
	cmp, err := h.read.CompareReleases(r.Context(), releaseID, candidateID)
	if err != nil {
		var noEv *app.NoEvidenceError
		switch {
		case errors.As(err, &noEv):
			writeProblem(w, http.StatusUnprocessableEntity, "release has no evidence", err.Error())
		case errors.Is(err, app.ErrEvidenceUnavailable):
			writeProblem(w, http.StatusBadGateway, "cannot verify evidence", err.Error())
		default:
			writeProblem(w, http.StatusInternalServerError, "cannot compare releases", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, toReleaseComparison(cmp))
}

func toReleaseComparison(c app.ReleaseComparison) gen.ReleaseComparison {
	bucket := func(entries []app.PostureEntry) *[]gen.PostureEntry {
		out := make([]gen.PostureEntry, 0, len(entries))
		for _, e := range entries {
			out = append(out, toPostureEntry(e))
		}
		return &out
	}
	return gen.ReleaseComparison{
		BaselineReleaseId:  strptr(c.BaselineReleaseID),
		CandidateReleaseId: strptr(c.CandidateReleaseID),
		Fixed:              bucket(c.Fixed),
		New:                bucket(c.New),
		Persisting:         bucket(c.Persisting),
	}
}

// GetBlastRadius handles GET /faultlines/{faultlineId}/blast-radius.
func (h *Handler) GetBlastRadius(w http.ResponseWriter, r *http.Request, faultlineID string) {
	releases, err := h.read.FaultlineBlastRadius(r.Context(), faultlineID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot read blast radius", err.Error())
		return
	}
	if releases == nil {
		releases = []string{}
	}
	writeJSON(w, http.StatusOK, releases)
}

// --- writes (triage) -----------------------------------------------------------------

// RaiseProposal handles POST /findings/{id}/proposals.
func (h *Handler) RaiseProposal(w http.ResponseWriter, r *http.Request, id string) {
	var body gen.RaiseProposalRequest
	if !decode(w, r, &body) {
		return
	}
	if !domain.Stance(body.Stance).Valid() {
		writeProblem(w, http.StatusBadRequest, "invalid stance", "unknown stance "+body.Stance)
		return
	}
	proposer, err := proposerFrom(body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid proposer", err.Error())
		return
	}
	rationale := ""
	if body.Rationale != nil {
		rationale = *body.Rationale
	}
	// A human's proposal is Asserted: a declaration Themis cannot re-derive. It changes no
	// behaviour today — a non-system proposal is never policy-auto-accepted regardless — but
	// it states the evidence honestly rather than leaving it unset.
	pid, err := h.write.RaiseProposal(r.Context(), domain.FindingID(id), proposer, domain.Stance(body.Stance), rationale, value.TrustAsserted)
	if err != nil {
		writeErr(w, "cannot raise proposal", err)
		return
	}
	pidStr := string(pid)
	writeJSON(w, http.StatusCreated, gen.RaiseProposalResponse{ProposalId: &pidStr})
}

// AcceptProposal handles POST /findings/{id}/proposals/{proposalId}/accept.
func (h *Handler) AcceptProposal(w http.ResponseWriter, r *http.Request, id, proposalID string) {
	decider, reviewBy, ok := decisionFrom(w, r)
	if !ok {
		return
	}
	if err := h.write.AcceptProposal(r.Context(), domain.FindingID(id), domain.ProposalID(proposalID), decider, reviewBy...); err != nil {
		writeErr(w, "cannot accept proposal", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RejectProposal handles POST /findings/{id}/proposals/{proposalId}/reject.
func (h *Handler) RejectProposal(w http.ResponseWriter, r *http.Request, id, proposalID string) {
	decider, ok := deciderFrom(w, r)
	if !ok {
		return
	}
	if err := h.write.RejectProposal(r.Context(), domain.FindingID(id), domain.ProposalID(proposalID), decider); err != nil {
		writeErr(w, "cannot reject proposal", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ResolveFinding handles POST /findings/{id}/resolve.
func (h *Handler) ResolveFinding(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.write.ResolveFinding(r.Context(), domain.FindingID(id)); err != nil {
		writeErr(w, "cannot resolve finding", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReopenFinding handles POST /findings/{id}/reopen.
func (h *Handler) ReopenFinding(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.write.ReopenFinding(r.Context(), domain.FindingID(id)); err != nil {
		writeErr(w, "cannot reopen finding", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ArchiveFinding handles POST /findings/{id}/archive.
func (h *Handler) ArchiveFinding(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.write.ArchiveFinding(r.Context(), domain.FindingID(id)); err != nil {
		writeErr(w, "cannot archive finding", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// aiReasonHeader carries why no proposal was produced on a 204 (AI-204-1). Advisory metadata,
// not a contract: an absent header simply means an older node.
const aiReasonHeader = "X-Themis-AI-Reason"

// RecommendPosition handles POST /findings/{id}/recommend — the on-demand AI seam
// (D8/D13, Revision 2). It invokes the Intelligence Gateway (when enabled) and records
// an ADVISORY AI proposal, never auto-accepted. When AI is disabled, unavailable, or
// declines, it returns 204 (no proposal) — the pipeline is unaffected.
func (h *Handler) RecommendPosition(w http.ResponseWriter, r *http.Request, id string) {
	pid, produced, reason, err := h.write.RecommendPosition(r.Context(), domain.FindingID(id))
	if err != nil {
		writeErr(w, "cannot recommend position", err)
		return
	}
	if !produced {
		// WHY, on the 204 (AI-204-1). "the model correctly declined" and "the provider is down"
		// are the same status code and opposite operator actions; a caller that ignores the
		// header behaves exactly as before.
		if reason != "" {
			w.Header().Set(aiReasonHeader, reason)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	pidStr := string(pid)
	writeJSON(w, http.StatusCreated, gen.RaiseProposalResponse{ProposalId: &pidStr})
}

// --- mappers + helpers ---------------------------------------------------------------

func toFindingView(f domain.Finding) gen.FindingView {
	id, rel, fl, cve, stage := string(f.ID()), f.ReleaseID(), f.FaultlineID(), f.CVE(), string(f.Stage())

	comps := toComponents(f.Components())
	positions := make([]gen.PositionView, 0, len(f.Positions()))
	for _, p := range f.Positions() {
		positions = append(positions, toPositionView(p))
	}
	proposals := make([]gen.ProposalView, 0, len(f.Proposals()))
	for _, p := range f.Proposals() {
		proposals = append(proposals, toProposalView(p))
	}

	view := gen.FindingView{
		Id: &id, ReleaseId: &rel, FaultlineId: &fl, Cve: &cve, Stage: &stage,
		Components: &comps, Positions: &positions, Proposals: &proposals,
	}
	if cur, ok := f.CurrentPosition(); ok {
		cv := toPositionView(cur)
		view.CurrentPosition = &cv
	}
	return view
}

func toPositionView(p domain.Position) gen.PositionView {
	version := p.Version()
	at := p.EstablishedAt()
	return gen.PositionView{
		Version:            &version,
		Stance:             strptr(string(p.Stance())),
		Rationale:          strptr(p.Rationale()),
		ActorKind:          strptr(string(p.Actor().Kind)),
		ActorId:            strptr(p.Actor().ID),
		AcceptedProposalId: strptr(string(p.Inputs().AcceptedProposalID)),
		FaultlineRef:       strptr(p.Inputs().FaultlineRef),
		EstablishedAt:      &at,
	}
}

func toProposalView(p domain.GovernanceProposal) gen.ProposalView {
	raised := p.RaisedAt()
	return gen.ProposalView{
		Id:           strptr(string(p.ID())),
		ProposerKind: strptr(string(p.Proposer().Kind)),
		ProposerId:   strptr(p.Proposer().ID),
		Stance:       strptr(string(p.Stance())),
		Rationale:    strptr(p.Rationale()),
		RaisedAt:     &raised,
		Status:       strptr(string(p.Status())),
		DecidedKind:  strptr(string(p.DecidedBy().Kind)),
		DecidedId:    strptr(p.DecidedBy().ID),
		// The trust class this proposal rests on (T2/T3). It is what the constitutional check
		// (T4) turns on, and it was invisible: a human was shown an AI proposal and a system
		// proposal side by side with nothing distinguishing re-derivable fact from a model's
		// reasoning. A guarantee nobody can see is one nobody can act on.
		EvidenceTrust: strptr(string(p.EvidenceTrust())),
	}
}

// toComponents maps matched components to the wire shape, carrying `source` — the only key that
// joins a component to its published fix (AI-GROUND-1).
func toComponents(in []domain.MatchedComponent) []gen.Component {
	out := make([]gen.Component, 0, len(in))
	for _, c := range in {
		out = append(out, gen.Component{
			Purl: strptr(c.PURL), Name: strptr(c.Name), Version: strptr(c.Version),
			Ecosystem: strptr(c.Ecosystem), Source: strptr(c.Source),
			ClaimClass: strptr(c.ClaimClass), DetectionOrigin: strptr(c.DetectionOrigin),
			VerdictState: verdictStatePtr(c.VerdictState), VerdictGrade: verdictGradePtr(c.VerdictGrade),
			VerdictReason: strptr(c.VerdictReason),
		})
	}
	return out
}

// toFixedVersions maps the selected fixes to the wire shape.
func toFixedVersions(in []app.FixedVersion) []gen.FixedVersion {
	out := make([]gen.FixedVersion, 0, len(in))
	for _, f := range in {
		pkg, ver := f.Package, f.Version
		out = append(out, gen.FixedVersion{Package: &pkg, Version: &ver})
	}
	return out
}

func toPostureEntry(e app.PostureEntry) gen.PostureEntry {
	has := e.HasPosition
	base := e.BaseScore
	mult := float32(e.Multiplier)
	eff := e.EffectivePriority
	res := e.ResidualPriority
	open := e.OpenCarriers
	out := gen.PostureEntry{
		FindingId:         strptr(string(e.FindingID)),
		FaultlineId:       strptr(e.FaultlineID),
		Cve:               strptr(e.CVE),
		Stage:             strptr(string(e.Stage)),
		Stance:            strptr(string(e.Stance)),
		HasPosition:       &has,
		BaseScore:         &base,
		BlastMultiplier:   &mult,
		EffectivePriority: &eff,
		ResidualPriority:  &res,
		OpenCarriers:      &open,
	}
	if len(e.Components) > 0 {
		comps := toComponents(e.Components)
		out.Components = &comps
	}
	// The band and the per-component fix selection (DASH-2 / PLAN-3): what turns this rollup from
	// a list of ids into something a dashboard can render in one call.
	if e.Band != "" {
		band := e.Band
		out.Band = &band
	}
	if len(e.Fixes) > 0 {
		fixes := toFixedVersions(e.Fixes)
		out.Fixes = &fixes
	}
	// Omitted when the Position rests on Observed evidence — an absent reservation reads as
	// "nothing to caveat", which is exactly right, and keeps the common row unchanged.
	if e.Reservation != "" {
		r := gen.PostureEntryReservation(e.Reservation)
		out.Reservation = &r
	}
	return out
}

// proposerFrom builds the proposer actor from the request (human by default; ai allowed).
// system/policy are internal-only proposers and are refused at the API boundary.
func proposerFrom(body gen.RaiseProposalRequest) (domain.Actor, error) {
	kind := domain.ActorHuman
	if body.ProposerKind != nil && *body.ProposerKind != "" {
		switch domain.ActorKind(*body.ProposerKind) {
		case domain.ActorHuman:
			kind = domain.ActorHuman
		case domain.ActorAI:
			kind = domain.ActorAI
		default:
			return domain.Actor{}, errors.New("proposer must be human or ai")
		}
	}
	id := "api"
	if body.ProposerId != nil && *body.ProposerId != "" {
		id = *body.ProposerId
	}
	return domain.Actor{Kind: kind, ID: id}, nil
}

// deciderFrom builds the deciding actor from the request body — the authorization-hook
// seam. Only a human decider is accepted via the API; a missing actor id is a bad request.
func deciderFrom(w http.ResponseWriter, r *http.Request) (domain.Actor, bool) {
	actor, _, ok := decisionFrom(w, r)
	return actor, ok
}

// decisionFrom decodes the decider AND the optional review-by date. Kept separate from
// deciderFrom so the reject path — which has no shelf life to state — is not handed a field it
// would have to ignore.
func decisionFrom(w http.ResponseWriter, r *http.Request) (domain.Actor, []time.Time, bool) {
	var body gen.DecisionRequest
	if !decode(w, r, &body) {
		return domain.Actor{}, nil, false
	}
	var reviewBy []time.Time
	if body.ReviewBy != nil && !body.ReviewBy.IsZero() {
		reviewBy = append(reviewBy, body.ReviewBy.UTC())
	}
	actor, ok := deciderActorFrom(w, &body)
	return actor, reviewBy, ok
}

func deciderActorFrom(w http.ResponseWriter, body *gen.DecisionRequest) (domain.Actor, bool) {
	if body.ActorId == "" {
		writeProblem(w, http.StatusBadRequest, "invalid decider", "actor_id is required")
		return domain.Actor{}, false
	}
	// The API accepts only human or ai deciders; policy/system are internal-only. The
	// ADR-fixed authority rule (only a human or a Governance-owned policy may decide —
	// D11) is enforced in the app, so an ai decider is refused there with 403.
	kind := domain.ActorHuman
	if body.ActorKind != nil && *body.ActorKind != "" {
		switch domain.ActorKind(*body.ActorKind) {
		case domain.ActorHuman:
			kind = domain.ActorHuman
		case domain.ActorAI:
			kind = domain.ActorAI
		default:
			writeProblem(w, http.StatusBadRequest, "invalid decider", "decider must be human or ai")
			return domain.Actor{}, false
		}
	}
	return domain.Actor{Kind: kind, ID: body.ActorId}, true
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
	case errors.Is(err, store.ErrNotFound), errors.Is(err, domain.ErrProposalNotFound):
		writeProblem(w, http.StatusNotFound, title, err.Error())
	case errors.Is(err, app.ErrUnauthorized):
		writeProblem(w, http.StatusForbidden, title, err.Error())
	case errors.Is(err, domain.ErrIllegalTransition),
		errors.Is(err, domain.ErrProposalNotOpen),
		errors.Is(err, domain.ErrDuplicateProposal):
		writeProblem(w, http.StatusConflict, title, err.Error())
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

func strptr(s string) *string { return &s }

// verdictStatePtr / verdictGradePtr map the mirrored verdict onto the wire enums, omitting
// empty values so a pre-feature row serializes exactly as before (absent = open, fail-safe).
func verdictStatePtr(s string) *gen.ComponentVerdictState {
	if s == "" {
		return nil
	}
	v := gen.ComponentVerdictState(s)
	return &v
}

func verdictGradePtr(s string) *gen.ComponentVerdictGrade {
	if s == "" {
		return nil
	}
	v := gen.ComponentVerdictGrade(s)
	return &v
}
