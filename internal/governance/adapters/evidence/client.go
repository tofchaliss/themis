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
	"time"

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

// SBOMsOfRelease lists the SBOM-kind evidence filed against a release with its filing time
// (EDR-REMEDIATION-01 D3: the upload outcome's baseline). Any failure is an error.
func (c *Client) SBOMsOfRelease(ctx context.Context, releaseID string) ([]app.SBOMRef, error) {
	var rows []struct {
		ID      string    `json:"id"`
		Kind    string    `json:"kind"`
		FiledAt time.Time `json:"filed_at"`
	}
	if err := c.getJSON(ctx, "/api/v1/evidence?release="+url.QueryEscape(releaseID), &rows); err != nil {
		return nil, err
	}
	var out []app.SBOMRef
	for _, r := range rows {
		if r.Kind == "sbom" && r.ID != "" {
			out = append(out, app.SBOMRef{ID: r.ID, FiledAt: r.FiledAt.UTC()})
		}
	}
	return out, nil
}

// InventoryPURLs returns the purls of one evidence document's canonical inventory.
func (c *Client) InventoryPURLs(ctx context.Context, evidenceID string) (map[string]bool, error) {
	var inv struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := c.getJSON(ctx, "/api/v1/evidence/"+url.PathEscape(evidenceID)+"/inventory", &inv); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(inv.Components))
	for _, comp := range inv.Components {
		if comp.PURL != "" {
			out[comp.PURL] = true
		}
	}
	return out, nil
}

func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("evidence: GET %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

var _ app.UploadEvidence = (*Client)(nil)
