package serializer

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

// ErrRollupUnsupported is returned for a format whose serializer cannot render a
// release-scoped rollup (D13.5's clear 400 — never a half-document). CSAF's product-tree
// rollup is COMM-VEX-1b; CycloneDX-VEX follows.
var ErrRollupUnsupported = errors.New("communication: format does not support a release rollup")

// RollupSerializer renders a release-scoped rollup artifact. A serializer opts in by
// implementing it beside Serializer; the registry type-asserts.
type RollupSerializer interface {
	RenderRollup(art domain.RollupArtifact) ([]byte, error)
}

// RenderRollup serializes the rollup in the requested format — ErrUnknownFormat when no
// serializer owns the format at all, ErrRollupUnsupported when one does but has no rollup
// form yet.
func (r *Registry) RenderRollup(format string, art domain.RollupArtifact) ([]byte, error) {
	s, ok := r.byFormat[format]
	if !ok {
		return nil, ErrUnknownFormat
	}
	rs, ok := s.(RollupSerializer)
	if !ok {
		return nil, ErrRollupUnsupported
	}
	return rs.RenderRollup(art)
}

// openvexRollupDoc is the multi-statement OpenVEX document (D13). Beside the standard
// fields it carries a namespaced extension block for the document's honesty-inline vintage
// (D13.2): what it covers and what it deliberately excluded.
type openvexRollupDoc struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Statements []openvexStatement `json:"statements"`
	Themis     openvexRollupMeta  `json:"x_themis"`
}

type openvexRollupMeta struct {
	ReleaseRef        string `json:"release_ref"` // the internal release id, for traceability (D13.4)
	Findings          int    `json:"findings_covered"`
	WithdrawnExcluded int    `json:"withdrawn_cves_excluded,omitempty"`
}

// RenderRollup renders the release rollup as one OpenVEX document: every finding exactly one
// statement (D13.3), the product identified by the Registry-derived purl (D13.4), open
// components as subcomponents, and the machine's knowledge as ANNOTATIONS folded into
// status_notes — informative, never the status (D13.1). Deterministic: the as-of is an input.
func (OpenVEX) RenderRollup(art domain.RollupArtifact) ([]byte, error) {
	stmts := make([]openvexStatement, 0, len(art.Statements))
	for _, s := range art.Statements {
		product := openvexProduct{ID: art.Product.PURL()}
		for _, purl := range s.Subcomponents {
			product.Subcomponents = append(product.Subcomponents, openvexComponent{ID: purl})
		}
		stmt := openvexStatement{
			Vulnerability: openvexVuln{Name: s.CVE},
			Products:      []openvexProduct{product},
			Status:        s.Status,
			StatusNotes:   rollupNotes(s),
		}
		if stmt.Status == "not_affected" {
			stmt.Justification = "vulnerable_code_not_in_execute_path"
		}
		stmts = append(stmts, stmt)
	}
	doc := openvexRollupDoc{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         themisNamespace + "/vex/release/" + art.Product.ReleaseID,
		Author:     "Themis",
		Timestamp:  art.AsOf.UTC().Format(time.RFC3339),
		Version:    1,
		Statements: stmts,
		Themis: openvexRollupMeta{
			ReleaseRef: art.Product.ReleaseID, Findings: len(art.Statements),
			WithdrawnExcluded: art.WithdrawnExcluded,
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// rollupNotes folds the rationale and the annotations into one status_notes string —
// rationale first (it is the decision's own words), annotations after, each clearly
// bracketed as context rather than assertion.
func rollupNotes(s domain.RollupStatement) string {
	parts := make([]string, 0, 1+len(s.Annotations))
	if s.Rationale != "" {
		parts = append(parts, s.Rationale)
	}
	for _, a := range s.Annotations {
		parts = append(parts, "[note: "+a+"]")
	}
	return strings.Join(parts, " ")
}
