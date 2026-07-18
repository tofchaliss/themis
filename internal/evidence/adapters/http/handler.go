// Package http exposes the Evidence context over REST, implementing the
// oapi-codegen-generated server interface (package gen) over the application
// service. It maps between the wire models and the domain, and renders a Problem
// error envelope with helpful rejections (EDR-EVIDENCE-01 D8).
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/evidence/adapters/http/gen"
	"github.com/themis-project/themis/internal/evidence/adapters/parser"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
)

// Handler implements gen.ServerInterface over the Evidence application service.
type Handler struct {
	svc *app.EvidenceService
}

// NewHandler builds a Handler.
func NewHandler(svc *app.EvidenceService) *Handler { return &Handler{svc: svc} }

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

// ListEvidence handles GET /evidence?release=.
func (h *Handler) ListEvidence(w http.ResponseWriter, r *http.Request, params gen.ListEvidenceParams) {
	list, err := h.svc.ListByRelease(r.Context(), params.Release)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "cannot list evidence", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, toSummaries(list))
}

// --- error mapping ---------------------------------------------------------

func writeRegisterError(w http.ResponseWriter, err error) {
	var ufe *parser.UnsupportedFormatError
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
			Purl: strptr(c.PURL.String()), Name: strptr(c.Name), Version: strptr(c.Version), Ecosystem: strptr(c.Ecosystem),
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
		out = append(out, gen.EvidenceSummary{Id: strptr(string(s.ID)), Kind: strptr(string(s.Kind)), Fingerprint: strptr(s.Fingerprint), FiledAt: &filed})
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
