// Package intelligence is Governance's client for the Intelligence Gateway's reactive
// API (D8/D13): it invokes the recommend_position capability over HTTP and decodes the
// advisory Proposal into Governance's own app.Recommendation — never importing the
// Intelligence context's packages (the JSON contract is the only coupling). It
// implements the app.PositionAdvisor port. A no-op sibling (NoopAdvisor) is the
// disable-gate alternative.
package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/themis-project/themis/internal/governance/app"
)

// Client invokes the Intelligence Gateway's reactive capability API.
type Client struct {
	baseURL    string
	capability string
	http       *http.Client
}

// NewClient builds a client against the Intelligence base URL (e.g.
// "http://intelligence:8086"). A nil http.Client falls back to http.DefaultClient.
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: baseURL, capability: "recommend_position", http: hc}
}

type wireProposal struct {
	Capability string  `json:"capability"`
	Stance     string  `json:"stance"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
	DecidedBy  string  `json:"decided_by"`
	Evidence   []struct {
		Kind string `json:"kind"`
		Ref  string `json:"ref"`
	} `json:"evidence"`
}

// RecommendPosition invokes recommend_position for a Finding. produced=false on a 204
// ("no proposal"). A transport/HTTP failure returns an error, which the caller treats
// as "disabled ≡ unavailable" (a safe no-proposal outcome).
func (c *Client) RecommendPosition(ctx context.Context, findingID string) (app.Recommendation, bool, error) {
	// The Selection shape (EDR-TRUST-01 T9). Governance's own app port is unchanged — it
	// still passes a finding id; constructing the Selection is this adapter's job, which is
	// exactly what an anti-corruption layer is for.
	reqBody, err := json.Marshal(map[string]any{
		"subject": map[string]any{"type": "finding", "ids": []string{findingID}},
	})
	if err != nil {
		return app.Recommendation{}, false, err
	}
	url := fmt.Sprintf("%s/api/v1/capabilities/%s/invoke", c.baseURL, c.capability)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return app.Recommendation{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return app.Recommendation{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNoContent {
		return app.Recommendation{}, false, nil // no proposal — a safe outcome
	}
	if resp.StatusCode != http.StatusOK {
		return app.Recommendation{}, false, fmt.Errorf("intelligence API: status %d", resp.StatusCode)
	}

	var wp wireProposal
	if err := json.NewDecoder(resp.Body).Decode(&wp); err != nil {
		return app.Recommendation{}, false, err
	}
	return app.Recommendation{
		Stance:     wp.Stance,
		Confidence: wp.Confidence,
		Reasoning:  wp.Reasoning,
		Capability: wp.Capability,
		DecidedBy:  wp.DecidedBy,
		Evidence:   evidenceRefs(wp),
	}, true, nil
}

// evidenceRefs extracts the cited references so Governance can Business-Verify them against
// its own truth before recording anything (EDR-TRUST-01 T8).
func evidenceRefs(wp wireProposal) []string {
	out := make([]string, 0, len(wp.Evidence))
	for _, e := range wp.Evidence {
		out = append(out, e.Ref)
	}
	return out
}
