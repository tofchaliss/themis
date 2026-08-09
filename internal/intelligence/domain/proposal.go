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
	// DecidedBy records which plan step produced the recommendation — "rule:<stance>"
	// (a deterministic short-circuit) or "llm:<stance>" (the model). It is the
	// testability hook for the two-step plan and the metric source for can't-determine.
	DecidedBy string
	// PrecedentsUsed is how many past Enterprise Positions grounded the LLM step — semantic
	// neighbours from the Operational Semantic Index (Δ3a) plus any exact-CVE fallback.
	//
	// It is the ONLY externally visible evidence that the retrieval plane contributed. Without it
	// Δ3a's whole claim — that our own governance history changes a recommendation — is
	// unfalsifiable from outside: the number was computed and then read by nothing.
	PrecedentsUsed int
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
	// RationaleWarnings lists identifier-shaped tokens the free-text Reasoning names that the
	// grounding does not contain (TRUST-8). Empty on a clean proposal.
	//
	// It is ADVISORY, never a rejection: the structured Evidence above passed Grounding
	// Verification, so the proposal is well-formed — this only marks that its narrative
	// mentions ids nobody supplied, which is the failure mode a reviewer cannot see. An empty
	// slice does not certify the narrative; it only says no ids were invented.
	RationaleWarnings []string
}
