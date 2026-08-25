// Package readapi's proposal writer is Intelligence's outbound WRITE seam to Governance
// (Δ4b D-Δ4b-1): the autonomous analyst raises an advisory Proposal on an existing Finding via
// the EXISTING POST /findings/{id}/proposals with proposer_kind: ai. It is the only place the
// node writes cross-context, so it carries the node's write-scoped key. Read clients elsewhere
// in this package send no key (inbound-edge auth is read-open for inter-service reads).
package readapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/intelligence/app"
)

// ProposalWriter raises autonomous advisory proposals against Governance.
type ProposalWriter struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewProposalWriter builds the writer against the Governance base URL. The apiKey is the node's
// write-scoped key (empty in an auth-off dev deployment).
func NewProposalWriter(baseURL, apiKey string, hc *http.Client) *ProposalWriter {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &ProposalWriter{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: hc}
}

type raiseProposalBody struct {
	Stance       string `json:"stance"`
	Rationale    string `json:"rationale,omitempty"`
	ProposerKind string `json:"proposer_kind"`
	ProposerID   string `json:"proposer_id,omitempty"`
}

// RaiseAIProposal posts an advisory proposal with proposer_kind: ai. A non-2xx is an error the
// caller (the sweep) treats as a per-Finding failure — one push failing must not stop the sweep.
func (w *ProposalWriter) RaiseAIProposal(ctx context.Context, findingID, stance, rationale string) error {
	body, err := json.Marshal(raiseProposalBody{
		Stance: stance, Rationale: rationale, ProposerKind: "ai", ProposerID: "autonomous-consistency-analyst",
	})
	if err != nil {
		return err
	}
	url := w.baseURL + "/api/v1/findings/" + findingID + "/proposals"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.apiKey != "" {
		req.Header.Set("X-API-Key", w.apiKey)
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("governance: raise proposal %s: status %d", findingID, resp.StatusCode)
	}
	return nil
}

var _ app.ProposalRaiser = (*ProposalWriter)(nil)
