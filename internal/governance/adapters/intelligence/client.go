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
	"strings"

	"github.com/themis-project/themis/internal/governance/app"
)

// Client invokes the Intelligence Gateway's reactive capability API.
type Client struct {
	baseURL    string
	apiKey     string
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

// WithAPIKey makes every invocation carry `X-API-Key` (EDR-SECURITY-01 F1). An empty key leaves
// the call unauthenticated — the auth-off development case.
//
// This seam is the one inter-service call of Governance's that is NOT a read: a capability
// invocation is a POST, so Intelligence's inbound edge (`RequireWriteScope`) refuses a
// read-only key with 403. A Governance node that both enables AI and runs against an
// authenticated Intelligence therefore needs a WRITE-capable (`admin`) key — which it reports
// here as a plain HTTP error that names the variable, because a refused invocation is otherwise
// indistinguishable from the Gateway being disabled (D13 treats "unavailable" as a safe
// no-proposal, and that is exactly how a 403 used to be swallowed).
func (c *Client) WithAPIKey(apiKey string) *Client {
	c.apiKey = strings.TrimSpace(apiKey)
	return c
}

type wireProposal struct {
	Capability string  `json:"capability"`
	Stance     string  `json:"stance"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
	DecidedBy  string  `json:"decided_by"`
	// RationaleWarnings: identifiers the free-text reasoning names that the Gateway's grounding
	// did not contain (EDR-TRUST-01 T8). Advisory — carried through so the human deciding sees
	// the caveat next to the narrative it applies to.
	RationaleWarnings []string `json:"rationale_warnings"`
	Evidence          []struct {
		Kind string `json:"kind"`
		Ref  string `json:"ref"`
	} `json:"evidence"`
}

// Headers the Gateway sets on a 204 to say why nothing was produced (AI-204-1). Absent from an
// older node, which simply yields an empty reason — the same behaviour as before.
const (
	gatewayReasonHeader = "X-Themis-AI-Reason"
	gatewayDetailHeader = "X-Themis-AI-Detail"
)

// RecommendPosition invokes recommend_position for a Finding. produced=false on a 204
// ("no proposal"). A transport/HTTP failure returns an error, which the caller treats
// as "disabled ≡ unavailable" (a safe no-proposal outcome).
func (c *Client) RecommendPosition(ctx context.Context, findingID string) (app.Recommendation, bool, app.NoProposal, error) {
	// The Selection shape (EDR-TRUST-01 T9). Governance's own app port is unchanged — it
	// still passes a finding id; constructing the Selection is this adapter's job, which is
	// exactly what an anti-corruption layer is for.
	reqBody, err := json.Marshal(map[string]any{
		"subject": map[string]any{"type": "finding", "ids": []string{findingID}},
	})
	if err != nil {
		return app.Recommendation{}, false, app.NoProposal{}, err
	}
	url := fmt.Sprintf("%s/api/v1/capabilities/%s/invoke", c.baseURL, c.capability)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return app.Recommendation{}, false, app.NoProposal{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return app.Recommendation{}, false, app.NoProposal{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNoContent {
		// The Gateway states WHY on the 204 (AI-204-1) in TWO headers, and they stay two fields
		// here. They were once flattened into "<reason>: <detail>" — the detail is worth having
		// (`provider_error` alone does not say the provider timed out at 60s) but concatenating
		// it changed the value's SHAPE from a closed enum to free text, and the dashboard's
		// exact-match lookup then rendered a `business_invalid` safety refusal as "the Gateway
		// stated no reason" (DEF_GOV_AI_REASON_COMPOSITE_BREAKS_TAXONOMY).
		return app.Recommendation{}, false, app.NoProposal{
			Reason: resp.Header.Get(gatewayReasonHeader),
			Detail: resp.Header.Get(gatewayDetailHeader),
		}, nil // no proposal — a safe outcome
	}
	if resp.StatusCode != http.StatusOK {
		return app.Recommendation{}, false, app.NoProposal{},
			fmt.Errorf("intelligence API: status %d%s", resp.StatusCode, c.credentialHint(resp.StatusCode))
	}

	var wp wireProposal
	if err := json.NewDecoder(resp.Body).Decode(&wp); err != nil {
		return app.Recommendation{}, false, app.NoProposal{}, err
	}
	return app.Recommendation{
		Stance:            wp.Stance,
		Confidence:        wp.Confidence,
		Reasoning:         wp.Reasoning,
		Capability:        wp.Capability,
		DecidedBy:         wp.DecidedBy,
		Evidence:          evidenceRefs(wp),
		RationaleWarnings: wp.RationaleWarnings,
	}, true, app.NoProposal{}, nil
}

// credentialHint names the likely cause of a 401/403 in the error itself. A capability
// invocation is a POST, so Intelligence requires a WRITE-capable key for it — which is why the
// 403 wording says so rather than repeating the read-scope advice of the read seams.
func (c *Client) credentialHint(status int) string {
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return ""
	}
	if c.apiKey == "" {
		return " — this invocation sent no X-API-Key; set THEMIS_API_KEY on this node (a capability invoke is a POST, so it needs a write-capable key)"
	}
	return " — this invocation sent an X-API-Key Intelligence refused; check THEMIS_API_KEY is current and write-capable (a capability invoke is a POST)"
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
