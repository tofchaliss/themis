// Package registry is the Communication context's client for Registry's read API: the
// upward name-chain walk (release → project → product) that gives a release rollup its
// customer-facing product identity (EDR-COMMUNICATION-01 D13.4). It fails CLOSED — any
// missing hop or blank name refuses the whole identity, because a customer document whose
// product line is a UUID is not degraded, it is useless. The deliberate OPPOSITE trade from
// Governance's blast-radius read, which fails open to 1.0×.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// Client walks Registry's read API for the name chain.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient builds a client against the Registry base URL (e.g. "http://registry:8082").
// A nil http.Client falls back to http.DefaultClient.
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

var _ app.ReleaseIdentityReader = (*Client)(nil)

type releaseView struct {
	ProjectID string `json:"project_id"`
	Version   string `json:"version"`
}

type projectView struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

type productView struct {
	Name string `json:"name"`
}

// ReleaseIdentity resolves the full name chain for a release. Three hops, one seam; any
// failure or blank field wraps app.ErrIncompleteIdentity so the caller's refusal names the
// D13.4 rule rather than a bare transport error.
func (c *Client) ReleaseIdentity(ctx context.Context, releaseID string) (domain.RollupProductRef, error) {
	var rel releaseView
	if err := c.get(ctx, "/api/v1/releases/"+releaseID, &rel); err != nil {
		return domain.RollupProductRef{}, fmt.Errorf("%w: release: %w", app.ErrIncompleteIdentity, err)
	}
	var proj projectView
	if err := c.get(ctx, "/api/v1/projects/"+rel.ProjectID, &proj); err != nil {
		return domain.RollupProductRef{}, fmt.Errorf("%w: project: %w", app.ErrIncompleteIdentity, err)
	}
	var prod productView
	if err := c.get(ctx, "/api/v1/products/"+proj.ProductID, &prod); err != nil {
		return domain.RollupProductRef{}, fmt.Errorf("%w: product: %w", app.ErrIncompleteIdentity, err)
	}
	ref := domain.RollupProductRef{
		Product: strings.TrimSpace(prod.Name), Project: strings.TrimSpace(proj.Name),
		Version: strings.TrimSpace(rel.Version), ReleaseID: releaseID,
	}
	if !ref.Complete() {
		return domain.RollupProductRef{}, fmt.Errorf("%w: a hop answered with a blank name", app.ErrIncompleteIdentity)
	}
	return ref, nil
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
