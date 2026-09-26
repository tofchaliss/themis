// Package http exposes the Governance context's triage + read API over REST, implementing
// the oapi-codegen server interface (package gen) over the app services. Writes drive the
// governed decision workflow (raise / accept / reject a proposal, lifecycle transitions);
// reads serve Findings, Positions, and the release-posture / blast-radius rollups. Renders
// a Problem error envelope. The ADR-fixed rule (only a human or a Governance-owned policy may
// decide) is enforced in the app (D11).
//
// The deciding actor is DERIVED FROM THE AUTHENTICATED PRINCIPAL, not from the request body —
// see actorProvenance. This doc comment used to say "a real deployment derives it from auth
// middleware", describing an intention nothing implemented: the recorded decider was whatever
// string the caller sent, and 138 rejections were eventually recorded against a pasted
// placeholder before anyone noticed (DEF_GOV_DECIDER_UNVERIFIED).
package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/platform/auth"
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
	// The vendor statements ride REGARDLESS of whether the knowledge half resolved, and before
	// the early return below: a blocked statement's whole purpose is to stay visible
	// (EDR-VEX-02 D2), so it must not be lost to an unrelated absence.
	if len(a.VendorStatements) > 0 {
		vs := make([]gen.VendorStatement, 0, len(a.VendorStatements))
		for _, v := range a.VendorStatements {
			vs = append(vs, gen.VendorStatement{
				Package: strptr(v.Package), Status: strptr(v.Status),
				Justification: strptr(v.Justification),
				ScopeFamily:   strptr(v.ScopeFamily), ScopeMajor: strptr(v.ScopeMajor),
				Applicability: (*gen.VendorStatementApplicability)(strptr(v.Applicability)),
			})
		}
		out.VendorStatements = &vs
	}
	// Attribution rides beside the vendor statements and for the same reason: an unresolved
	// attribution is precisely the case where the rest of the drawer has least to say, so it
	// must not depend on anything else resolving (EDR-ATTRIBUTION-01 D10). Omitted only when it
	// could not be derived at all — an absent status means Knowledge was unreachable, not that
	// the carrier question was answered.
	if a.Attribution.Status != "" {
		att := gen.Attribution{
			Status:     (*gen.AttributionStatus)(strptr(a.Attribution.Status)),
			Carriers:   &a.Attribution.Carriers,
			Components: &a.Attribution.Components,
		}
		if len(a.Attribution.UnresolvedBecause) > 0 {
			att.UnresolvedBecause = &a.Attribution.UnresolvedBecause
		}
		out.Attribution = &att
	}
	k := a.Knowledge
	if k.FaultlineID == "" {
		return out
	}
	ranges, fixes := k.AffectedRanges, k.FixedVersions
	carriers := k.CarrierProducts
	kev, pub := k.KEV, k.ExploitPublic
	cvss, epss := float32(k.CVSSScore), float32(k.EPSS)
	kn := gen.FaultlineKnowledge{
		FaultlineId: strptr(k.FaultlineID), Cve: strptr(k.CVE), Severity: strptr(k.Severity),
		Summary:   strptr(k.Summary),
		CvssScore: &cvss, Epss: &epss, Kev: &kev, ExploitPublic: &pub,
		AffectedRanges: &ranges, FixedVersions: &fixes,
		CarrierProducts: &carriers,
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
	proposer, err := proposerFrom(r.Context(), body)
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
	var pid domain.ProposalID
	if body.Evidence != nil {
		// EDR-HARNESS-01 (D-I-5): a HUMAN proposal whose evidence basis is a
		// commissioned harness execution. The trust class is the one the
		// intake DERIVED; Governance refuses any other. The service checks
		// the commission correspondence and Business-Verifies the refs.
		pid, err = h.write.RaiseHarnessProposal(r.Context(), domain.FindingID(id), proposer, domain.Stance(body.Stance), rationale, fromHarnessEvidence(*body.Evidence), harnessTrust(body))
		if err != nil {
			writeHarnessErr(w, "cannot raise proposal", err)
			return
		}
	} else {
		pid, err = h.write.RaiseProposal(r.Context(), domain.FindingID(id), proposer, domain.Stance(body.Stance), rationale, value.TrustAsserted)
		if err != nil {
			writeErr(w, "cannot raise proposal", err)
			return
		}
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

// The two headers carrying why no proposal was produced on a 204 (AI-204-1). Advisory metadata,
// not a contract: an absent header simply means an older node. They are the SAME two headers the
// Gateway sets, re-emitted unflattened — a consumer switches on the reason and displays the
// detail, and neither has to parse the other out of one string.
const (
	aiReasonHeader = "X-Themis-AI-Reason"
	aiDetailHeader = "X-Themis-AI-Detail"
)

// RecommendPosition handles POST /findings/{id}/recommend — the on-demand AI seam
// (D8/D13, Revision 2). It invokes the Intelligence Gateway (when enabled) and records
// an ADVISORY AI proposal, never auto-accepted. When AI is disabled, unavailable, or
// declines, it returns 204 (no proposal) — the pipeline is unaffected.
func (h *Handler) RecommendPosition(w http.ResponseWriter, r *http.Request, id string) {
	pid, produced, no, err := h.write.RecommendPosition(r.Context(), domain.FindingID(id))
	if err != nil {
		writeErr(w, "cannot recommend position", err)
		return
	}
	if !produced {
		// WHY, on the 204 (AI-204-1). "the model correctly declined" and "the provider is down"
		// are the same status code and opposite operator actions; a caller that ignores the
		// headers behaves exactly as before.
		if no.Reason != "" {
			w.Header().Set(aiReasonHeader, no.Reason)
		}
		if d := headerText(no.Detail); d != "" {
			w.Header().Set(aiDetailHeader, d)
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

	// ACTIVE components only. This view feeds the drawer and, through the assessment, the AI's
	// grounding — a withdrawn twin in either is a match the estate has already retracted
	// (KN-SCAN-4(b)). The aggregate keeps the row; no projection shows it.
	comps := toComponents(f.ActiveComponents())
	positions := make([]gen.PositionView, 0, len(f.Positions()))
	for _, p := range f.Positions() {
		positions = append(positions, toPositionView(p))
	}
	proposals := make([]gen.ProposalView, 0, len(f.Proposals()))
	for _, p := range f.Proposals() {
		proposals = append(proposals, toProposalView(p))
	}
	commissions := make([]gen.CommissionView, 0, len(f.Commissions()))
	for _, c := range f.Commissions() {
		commissions = append(commissions, toCommissionView(c))
	}

	view := gen.FindingView{
		Id: &id, ReleaseId: &rel, FaultlineId: &fl, Cve: &cve, Stage: &stage,
		Components: &comps, Positions: &positions, Proposals: &proposals, Commissions: &commissions,
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
	v := gen.ProposalView{
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
	if ev := p.HarnessEvidence(); ev != nil {
		v.CommissionId = strptr(string(ev.CommissionID))
		v.HarnessEvidence = toHarnessEvidenceView(ev)
	}
	return v
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

// toFixedVersions maps the selected fixes to the wire shape, carrying the fix's WORLD so a
// consumer can pair each fix with the occurrence it applies to (EDR-VERDICT-01 D8) instead of
// guessing from version shape.
func toFixedVersions(in []app.FixedVersion) []gen.FixedVersion {
	out := make([]gen.FixedVersion, 0, len(in))
	for _, f := range in {
		pkg, ver := f.Package, f.Version
		fv := gen.FixedVersion{Package: &pkg, Version: &ver}
		if f.Ecosystem != "" {
			eco := f.Ecosystem
			fv.Ecosystem = &eco
		}
		out = append(out, fv)
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
	if e.PositionVersion > 0 {
		pv := e.PositionVersion
		out.PositionVersion = &pv
	}
	if e.PositionRationale != "" {
		pr := e.PositionRationale
		out.PositionRationale = &pr
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

// Actor-id provenance prefixes (EDR-SECURITY-01 D10, DEF_GOV_DECIDER_UNVERIFIED). Every actor id
// Governance records through the API carries one, so the recorded provenance is machine-readable
// and a decision can never be mistaken for authenticated when authentication did not happen.
const (
	// authenticatedActorPrefix marks an id derived from the AUTHENTICATED principal. Only the
	// server can produce it — no request body reaches this form.
	authenticatedActorPrefix = "key:"
	// unauthenticatedActorPrefix marks a caller-declared id accepted because auth is disabled
	// (single-context dev). It is deliberately ugly: an unverified identity must not be able to
	// look like a verified one, and the prefix is applied whatever the caller sends, so a body
	// claiming "key:…" becomes "dev:key:…" rather than forging provenance.
	unauthenticatedActorPrefix = "dev:"
)

// actorProvenance resolves the identity a Governance record is attributed to, binding it to the
// authenticated principal wherever one exists.
//
// WHY THIS EXISTS. Until 2026-09-21 the recorded actor was whatever string the caller sent. The
// API key authenticated the CALLER and the audit trail recorded a self-declaration, with nothing
// relating the two — so any string at all landed as the person who authorized a governed change.
// It was found the way these things are found: a cleanup command was pasted with its example
// value intact and 138 rejections were recorded as decided by `your.name@example.com`.
//
// The identity was already there and already named for this: `auth.Principal.KeyID` is documented
// as "the auditable actor id (CON-0016 traceability)". The gap was that this package never read it.
//
// The invariant: every recorded actor id is explicit, machine-identifiable, and states whether
// authentication actually happened. Auth is optional by design (`THEMIS_AUTH_DATABASE_DSN` unset
// = disabled for single-context dev), so the unauthenticated path is supported rather than
// refused — but it is MARKED, never silently dressed up as a production identity. `ok` is false
// only when nothing at all identifies the actor.
func actorProvenance(ctx context.Context, declared string) (string, bool) {
	if p, ok := auth.PrincipalFrom(ctx); ok && p.KeyID != "" {
		// The principal wins outright and the declared value is ignored: a value the server
		// cannot verify must not be able to overwrite one it can.
		return authenticatedActorPrefix + p.KeyID, true
	}
	declared = strings.TrimSpace(declared)
	if declared == "" {
		return "", false
	}
	return unauthenticatedActorPrefix + declared, true
}

// proposerFrom builds the proposer actor from the request (human by default; ai allowed).
// system/policy are internal-only proposers and are refused at the API boundary.
//
// The proposer is bound to the authenticated principal for the same reason the decider is: a
// raised proposal is an audit record too, and this function used to DEFAULT the id to the literal
// "api" — provenance fabricated from no input whatever. Unlike the decider path it still accepts
// a missing id, because proposal-raising has always worked without one and breaking that is not
// this change's business; what it records instead is `dev:api`, which is honest about being an
// unauthenticated caller that declared nothing.
func proposerFrom(ctx context.Context, body gen.RaiseProposalRequest) (domain.Actor, error) {
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
	declared := "api"
	if body.ProposerId != nil && *body.ProposerId != "" {
		declared = *body.ProposerId
	}
	id, ok := actorProvenance(ctx, declared)
	if !ok {
		return domain.Actor{}, errors.New("proposer identity could not be established")
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
	actor, ok := deciderActorFrom(w, r, &body)
	return actor, reviewBy, ok
}

func deciderActorFrom(w http.ResponseWriter, r *http.Request, body *gen.DecisionRequest) (domain.Actor, bool) {
	// Bound to the authenticated principal when there is one; `actor_id` is then ignored, because
	// the server must not record an identity it cannot verify over one it can. With auth disabled
	// the declared id is accepted and marked `dev:`.
	id, ok := actorProvenance(r.Context(), body.ActorId)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid decider",
			"actor_id is required when authentication is disabled")
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
	return domain.Actor{Kind: kind, ID: id}, true
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

// headerText makes a free-text diagnostic safe to carry in an HTTP header VALUE.
//
// Header values are effectively latin-1 at the browser boundary (RFC 9110 leaves non-ASCII
// opaque), so UTF-8 punctuation arrives mangled. Measured on the deployment 2026-09-22: the
// dashboard rendered "zero carriers) â no evidence any component carries the flaw" for a
// detail whose JSON-delivered twin on the same page was perfect. The domain writes good UTF-8;
// it is the TRANSPORT that cannot carry it, so the folding belongs at this boundary and nowhere
// else — the log keeps the original text either way.
//
// The reason header needs none of this: it is a closed ASCII taxonomy by construction.
//
// Duplicated from the Intelligence adapter DELIBERATELY: the two are different bounded
// contexts and may not import each other, and a shared package for twenty lines of
// transport hygiene would be a worse trade than the copy.
func headerText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\u2014' || r == '\u2013' || r == '\u2212':
			b.WriteByte('-')
		case r == '\u2019' || r == '\u2018':
			b.WriteByte('\'')
		case r == '\u201c' || r == '\u201d':
			b.WriteByte('"')
		case r == '\u2026':
			b.WriteString("...")
		case r < 0x20 || r > 0x7e:
			// Anything else outside printable ASCII is dropped rather than mangled. A header is
			// a diagnostic pointer, not the record; mojibake in the operator's face is worse
			// than a missing glyph, and the full string is in the telemetry.
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
