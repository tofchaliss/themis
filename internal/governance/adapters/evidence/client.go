// Package evidence is the Governance context's client for Evidence's read API
// (EDR-GOVERNANCE-01 D16): it reads whether any evidence is filed against a release over
// HTTP and implements the app EvidencePresenceReader port — the honesty guard under the
// release-comparison read. It never imports the Evidence context or touches its tables
// (Book III §3.5) — the two collaborate solely via the read API.
package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/themis-project/themis/internal/governance/app"
)

// Client reads evidence presence from an Evidence service.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient builds a client against the Evidence base URL (e.g. http://evidence:8081).
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// HasEvidence reports whether any evidence document is filed against the release, via
// Evidence's list read (`GET /evidence?release=`). Any failure is an error, never a false —
// the caller's guard fails closed, and this client must not convert an outage into
// "no evidence" (which the compare would then refuse with the wrong reason).
func (c *Client) HasEvidence(ctx context.Context, releaseID string) (bool, error) {
	reqURL := c.baseURL + "/api/v1/evidence?release=" + url.QueryEscape(releaseID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("evidence: list for release %s: status %d", releaseID, resp.StatusCode)
	}

	var rows []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

var _ app.EvidencePresenceReader = (*Client)(nil)
