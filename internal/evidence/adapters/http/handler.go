// Package http exposes the Evidence context over REST, implementing the
// oapi-codegen-generated server interface (package gen) over the application
// service. It maps between the wire models and the domain, and renders a Problem
// error envelope with helpful rejections (EDR-EVIDENCE-01 D8).
package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/evidence/adapters/http/gen"
	"github.com/themis-project/themis/internal/evidence/adapters/parser"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// ReleaseOwnership answers which Product owns a Release — the read `POST /evidence`
// needs to authorize a `product:<id>` key against the release it names
// (EDR-INTAKE-01 B7: "the old door is not a way around the new one"). Satisfied by
// the registry read seam the composition root already wires (subjectref.Registry).
//
// An unknown release is an empty id and a nil error, the seam's own contract.
type ReleaseOwnership interface {
	ProductOfRelease(ctx context.Context, releaseID string) (string, error)
}

// Handler implements gen.ServerInterface over the Evidence application service.
type Handler struct {
	svc *app.EvidenceService
	// intake serves the single intake door (EDR-INTAKE-01 D1). nil ⇒ `POST /intake`
	// refuses honestly rather than 404-ing or pretending to accept: a door that
	// answers is a door a client will send a 60 MB SBOM through.
	intake *Intake
	// owner resolves a release to its owning Product. nil ⇒ a product-scoped key is
	// REFUSED on `POST /evidence`, because an ownership that cannot be established
	// is not an ownership that can be checked (fail-closed, B7). `admin` keys and
	// auth-disabled nodes never ask, so neither is affected.
	owner ReleaseOwnership
}

// NewHandler builds a Handler.
func NewHandler(svc *app.EvidenceService) *Handler { return &Handler{svc: svc} }

// WithIntake wires the intake door and returns the handler for chaining.
func (h *Handler) WithIntake(i *Intake) *Handler {
	h.intake = i
	return h
}

// WithReleaseOwnership wires the release→product read `POST /evidence` authorizes
// with, and returns the handler for chaining.
func (h *Handler) WithReleaseOwnership(o ReleaseOwnership) *Handler {
	h.owner = o
	return h
}

// Router returns an http.Handler serving the Evidence routes; mount it under the
// OpenAPI base path (/api/v1).
func (h *Handler) Router() http.Handler { return gen.Handler(h) }

// RegisterEvidence handles POST /evidence.
func (h *Handler) RegisterEvidence(w http.ResponseWriter, r *http.Request) {
	var req gen.RegisterEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error(), nil)
		return
	}
	// The ownership check, before the write (B7). The old door rested on the
	// method-based write floor, which sees a principal and no resource — so a
	// `product:<A>` key could file against product B's release just by naming its
	// id. That was a gap TODAY, not one `create_release` introduced, and it is
	// closed on both doors in the same change.
	if !h.authorizeRelease(w, r, req.SubjectReleaseId) {
		return
	}
	cmd := app.RegisterCommand{
		Raw:              []byte(req.Document),
		Kind:             domain.Kind(req.Kind),
		SubjectReleaseID: req.SubjectReleaseId,
		SpecVersion:      strval(req.SpecVersion),
		ExpectedChecksum: strval(req.ExpectedChecksum),
		Provenance: domain.Provenance{
			Source:      strval(req.ProvenanceSource),
			ImageDigest: strval(req.ProvenanceImageDigest),
		},
	}
	if req.Format != nil {
		cmd.Format = string(*req.Format)
	}

	res, err := h.svc.Register(r.Context(), cmd)
	if err != nil {
		writeRegisterError(w, err)
		return
	}
	status := http.StatusCreated
	if !res.Created {
		status = http.StatusOK
	}
	writeJSON(w, status, gen.RegisterEvidenceResponse{Id: string(res.ID), Created: res.Created})
}

// GetEvidence handles GET /evidence/{id}.
func (h *Handler) GetEvidence(w http.ResponseWriter, r *http.Request, id string) {
	e, err := h.svc.GetEvidence(r.Context(), domain.EvidenceID(id))
	if err != nil {
		writeReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toFacts(e))
}

// GetEvidenceInventory handles GET /evidence/{id}/inventory.
func (h *Handler) GetEvidenceInventory(w http.ResponseWriter, r *http.Request, id string) {
	inv, err := h.svc.GetInventory(r.Context(), domain.EvidenceID(id))
	if err != nil {
		writeReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toInventory(inv))
}

// GetEvidenceDocument handles GET /evidence/{id}/document — the raw stored bytes + kind, the
// read path Knowledge uses to parse an uploaded VEX (EDR-VEX-01 D1). Evidence serves the
// bytes as-is; it does not parse them.
func (h *Handler) GetEvidenceDocument(w http.ResponseWriter, r *http.Request, id string) {
	kind, doc, err := h.svc.GetDocument(r.Context(), domain.EvidenceID(id))
	if err != nil {
		writeReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, gen.Document{Kind: kind, Document: string(doc)})
}

// ListEvidence handles GET /evidence?release=.
func (h *Handler) ListEvidence(w http.ResponseWriter, r *http.Request, params gen.ListEvidenceParams) {
	list, err := h.svc.ListByRelease(r.Context(), params.Release)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot list evidence", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, toSummaries(list))
}

// --- product-ownership authorization on the old door (EDR-INTAKE-01 B7) ----

// unauthorizedReleaseDetail is what this door's authorization refusal says, in EVERY
// case: another product's release, a release that does not exist, and an ownership
// that could not be read are ONE answer. For a `product:<P>` key those are
// indistinguishable by decision (B3 applied to ids exactly as to names, rows 17-18),
// so the string is a constant and names nothing about the estate.
const unauthorizedReleaseDetail = "this key is not authorized for the product that owns the release this request names; " +
	"a product-scoped key may file evidence only for its own product"

// authorizeRelease reports whether the request may proceed, having already written
// the refusal otherwise.
//
// The order mirrors the intake door's: no principal (auth disabled at the inbound
// edge — dev only, and already open) and `admin` pass with no Registry read at all,
// so neither sees any change, including the `422 unknown subject release` an unknown
// release has always answered here. Only a confined key pays for the ownership hop,
// and for it every outcome but "the release belongs to my product" is the same `403`.
func (h *Handler) authorizeRelease(w http.ResponseWriter, r *http.Request, releaseID string) bool {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsAdmin() {
		return true
	}
	productID := ""
	if h.owner != nil {
		if id, err := h.owner.ProductOfRelease(r.Context(), releaseID); err == nil {
			productID = id
		}
	}
	// An empty id covers all three fail-closed cases (no seam, an unreadable seam, no
	// such release) and is refused on its own account rather than left to the
	// principal: a check that rests on a key never matching the empty product is a
	// check resting on a coincidence.
	if productID == "" || !p.AuthorizeProduct(productID) {
		writeProblem(w, http.StatusForbidden, "unauthorized", unauthorizedReleaseDetail, nil)
		return false
	}
	return true
}

// --- error mapping ---------------------------------------------------------

func writeRegisterError(w http.ResponseWriter, err error) {
	var ufe *parser.UnsupportedFormatError
	var cfe *app.ContentFiledElsewhereError
	switch {
	case errors.As(err, &ufe):
		supported := make([]string, len(ufe.Supported))
		for i, f := range ufe.Supported {
			supported[i] = string(f)
		}
		writeProblem(w, http.StatusUnprocessableEntity, "unsupported SBOM format", err.Error(), supported)
	case errors.Is(err, app.ErrUnknownSubject):
		writeProblem(w, http.StatusUnprocessableEntity, "unknown subject release", err.Error(), nil)
	case errors.Is(err, app.ErrRejected):
		writeProblem(w, http.StatusUnprocessableEntity, "artifact rejected by trust gate", err.Error(), nil)
	case errors.As(err, &cfe):
		// 409, never a silent created=false: the caller's release received nothing (D3 note).
		writeProblem(w, http.StatusConflict, "content already filed against another release", err.Error(), nil)
	default:
		writeProblem(w, http.StatusBadRequest, "cannot register evidence", err.Error(), nil)
	}
}

func writeReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "evidence not found", err.Error(), nil)
		return
	}
	writeProblem(w, http.StatusInternalServerError, "cannot read evidence", err.Error(), nil)
}

// --- mappers ---------------------------------------------------------------

func toFacts(e domain.Evidence) gen.EvidenceFacts {
	filed := e.FiledAt()
	return gen.EvidenceFacts{
		Id:                    strptr(string(e.ID())),
		Kind:                  strptr(string(e.Kind())),
		SubjectReleaseId:      strptr(e.Subject().ReleaseID),
		Fingerprint:           strptr(e.Fingerprint().String()),
		TrustStatus:           strptr(string(e.Trust())),
		ProvenanceSource:      strptr(e.Provenance().Source),
		ProvenanceImageDigest: strptr(e.Provenance().ImageDigest),
		FiledAt:               &filed,
	}
}

func toInventory(inv domain.Inventory) gen.Inventory {
	comps := make([]gen.Component, 0, len(inv.Components()))
	for _, c := range inv.Components() {
		comps = append(comps, gen.Component{
			Purl: strptr(c.PURL.String()), Name: strptr(c.Name), Version: strptr(c.Version), Ecosystem: strptr(c.Ecosystem), Source: strptr(c.Source),
		})
	}
	edges := make([]gen.DependencyEdge, 0, len(inv.Dependencies()))
	for _, e := range inv.Dependencies() {
		edges = append(edges, gen.DependencyEdge{From: strptr(e.From.String()), To: strptr(e.To.String()), Relationship: strptr(e.Relationship)})
	}
	return gen.Inventory{Components: &comps, Dependencies: &edges}
}

func toSummaries(list []app.EvidenceSummary) []gen.EvidenceSummary {
	out := make([]gen.EvidenceSummary, 0, len(list))
	for _, s := range list {
		filed := s.FiledAt
		out = append(out, gen.EvidenceSummary{Id: strptr(string(s.ID)), Kind: strptr(string(s.Kind)), Fingerprint: strptr(s.Fingerprint), ProvenanceSource: strptr(s.ProvenanceSource), FiledAt: &filed})
	}
	return out
}

// --- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string, supported []string) {
	p := gen.Problem{Title: strptr(title), Detail: strptr(detail)}
	if len(supported) > 0 {
		p.SupportedFormats = &supported
	}
	writeJSON(w, status, p)
}

func strptr(s string) *string { return &s }

func strval(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
