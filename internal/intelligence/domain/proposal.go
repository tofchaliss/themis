package domain

import "time"

// Recommendation is the structured core of a Proposal: the proposed disposition
// Stance for a specific Finding. The decision is always structured (D2) — raw
// natural language never carries it; only Reasoning (below) is free text.
type Recommendation struct {
	FindingID string
	Stance    Stance
}

// Evidence is one enterprise fact the recommendation cites. Every Ref must exist in
// the grounding AssembledContext — an evidence citation to something not assembled
// is a hallucination and is rejected by stage-2 validation (D7).
type Evidence struct {
	Kind string // e.g. "faultline", "cve", "signal"
	Ref  string // the grounded identifier
}

// Metadata is the execution provenance carried for observability (D9) and as inputs
// the enterprise-owned governance policy weighs (D8). It never contains sensitive
// prompt content (D10).
type Metadata struct {
	CorrelationID string
	Provider      string
	Model         string
	TokensUsed    int
	Duration      time.Duration
}

// Proposal is Intelligence's only output: a structured, schema-validated advisory
// Proposal (D2 · INT-0057) with a fixed envelope. It is an advisory transport that
// the consuming context records as its own; Intelligence writes no truth (D1).
type Proposal struct {
	Capability     string // "id@version"
	Recommendation Recommendation
	Confidence     float64
	Evidence       []Evidence
	Reasoning      string
	Metadata       Metadata
}
