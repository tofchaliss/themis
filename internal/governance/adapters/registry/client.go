// Package registry is the Governance context's client for Registry's read API: the
// blast-radius rollup (EDR-ESTATE-01 C2/D7 — how many unique customers a release reaches,
// implementing the app BlastRadiusReader port) and the upward hop release → project → product
// that confines a `product:<id>` key to its own product's Findings (EDR-DELIVERY-01 N-M0) and
// names the owners on `governance.release_evaluated.v1` (N-M2b). It
// never imports the Registry context or touches its tables (Book III §3.5) — the two
// collaborate solely via the read API.
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

type releaseView struct {
	ProjectID string `json:"project_id"`
}

type projectView struct {
	ProductID string `json:"product_id"`
}

// ProductOfRelease walks the two upward hops of Registry's identity chain — release →
// `project_id`, project → `product_id` — and returns the owning product id.
//
// It is the resource→product resolution that `auth.Principal.AuthorizeWrite` could not do
// (EDR-SECURITY-01 D4 realization note, EDR-HARNESS-01 D4's carried gap): the Governance write
// routes key on a Finding, and a product-scoped key may only write to its own product's
// Findings. It fails CLOSED — a transport failure, a non-200, or a blank hop is an error, never
// an empty product id, because the caller turns "cannot resolve" into a refusal and a blank
// string would compare equal to a blank scope. The deliberate OPPOSITE trade from BlastRadius
// above, which fails open to 1.0×: over-stating priority is a nuisance, granting a write to the
// wrong product is a breach.
func (c *Client) ProductOfRelease(ctx context.Context, releaseID string) (string, error) {
	productID, _, err := c.ProductAndProjectOfRelease(ctx, releaseID)
	return productID, err
}

// ProductAndProjectOfRelease walks the same two hops and returns BOTH ids.
//
// It is the full answer the hops already produce: `governance.release_evaluated.v1` names the
// project as well as the product (EDR-DELIVERY-01 M2-2), and the project id is read on the way
// to the product anyway — throwing it away and asking again would be two more round trips for a
// fact this call already holds. ProductOfRelease is the narrow view over it, so "how does
// Governance resolve a release's owners" keeps ONE implementation and one set of refusals.
//
// Fails CLOSED at every step: a transport failure, a non-200 or a blank hop is an error, never a
// blank id. The release-evaluation worker turns that into a deferral and retries; publishing an
// empty product id would state as fact that the Release belongs to nothing.
func (c *Client) ProductAndProjectOfRelease(ctx context.Context, releaseID string) (string, string, error) {
	if releaseID == "" {
		return "", "", fmt.Errorf("registry: product-of-release: no release id")
	}
	var rel releaseView
	if err := c.get(ctx, "/api/v1/releases/"+releaseID, &rel); err != nil {
		return "", "", fmt.Errorf("registry: release %s: %w", releaseID, err)
	}
	if rel.ProjectID == "" {
		return "", "", fmt.Errorf("registry: release %s: no project id", releaseID)
	}
	var proj projectView
	if err := c.get(ctx, "/api/v1/projects/"+rel.ProjectID, &proj); err != nil {
		return "", "", fmt.Errorf("registry: project %s: %w", rel.ProjectID, err)
	}
	if proj.ProductID == "" {
		return "", "", fmt.Errorf("registry: project %s: no product id", rel.ProjectID)
	}
	return proj.ProductID, rel.ProjectID, nil
}

func (c *Client) get(ctx context.Context, path string, into any) error {
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
		return fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

var (
	_ app.BlastRadiusReader       = (*Client)(nil)
	_ app.ReleaseIdentityResolver = (*Client)(nil)
)
