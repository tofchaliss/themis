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
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// Client walks Registry's read API for the name chain.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// defaultTimeout bounds one hop of the name chain when the caller supplies no client of its own.
// http.DefaultClient has none, and three unbounded hops sit between a rollup request and its
// answer.
const defaultTimeout = 30 * time.Second

// NewClient builds a client against the Registry base URL (e.g. "http://registry:8082").
// A nil http.Client falls back to one with defaultTimeout.
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// WithAPIKey makes every hop carry `X-API-Key`. An empty key leaves the reads unauthenticated (the
// auth-off development case).
//
// On an estate with `THEMIS_AUTH_REQUIRED=1` an unauthenticated hop answers 401, and because this
// seam fails CLOSED (D13.4), the whole release identity refuses and no rollup can be published —
// the credential is what keeps a correct refusal from being indistinguishable from a missing
// product. A READ-ONLY key is enough; this client performs no write.
func (c *Client) WithAPIKey(apiKey string) *Client {
	c.apiKey = strings.TrimSpace(apiKey)
	return c
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
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d%s", path, resp.StatusCode, c.credentialHint(resp.StatusCode))
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// credentialHint names the likely cause of a 401/403 in the error itself, so a refused identity does
// not read as a missing one.
func (c *Client) credentialHint(status int) string {
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return ""
	}
	if c.apiKey == "" {
		return " — this read sent no X-API-Key; set THEMIS_API_KEY on this node (a read-scoped key is enough)"
	}
	return " — this read sent an X-API-Key Registry refused; check THEMIS_API_KEY is current and has read scope"
}
