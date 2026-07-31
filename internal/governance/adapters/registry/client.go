// Package registry is the Governance context's client for Registry's blast-radius read API
// (EDR-ESTATE-01 C2/D7): it reads how many unique customers a release reaches over HTTP and
// implements the app BlastRadiusReader port. It never imports the Registry context or touches
// its tables (Book III §3.5) — the two collaborate solely via the read API.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/governance/app"
)

// Client reads blast radius from a Registry service.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient builds a client against the Registry base URL (e.g. http://registry:8082).
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

type blastRadiusResponse struct {
	UniqueCustomers int `json:"unique_customers"`
}

// BlastRadius fetches the count of unique customers a release reaches via Registry's estate
// read API.
func (c *Client) BlastRadius(ctx context.Context, releaseID string) (int, error) {
	url := c.baseURL + "/api/v1/releases/" + releaseID + "/blast-radius"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("registry: blast-radius %s: status %d", releaseID, resp.StatusCode)
	}

	var body blastRadiusResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, err
	}
	return body.UniqueCustomers, nil
}

var _ app.BlastRadiusReader = (*Client)(nil)
