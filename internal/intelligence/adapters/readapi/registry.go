package readapi

// The Registry client for the Δ4b autonomous sweep (D-Δ4b-2): it enumerates every release id in
// the estate so the analyst can scan their postures. Registry has no flat "all releases" read, so
// this walks products → projects → releases over the existing read API — the same composition the
// analyst is designed around (it needs no new Governance/Registry endpoint). Read-only; it carries
// the node's `X-API-Key` when one is configured (EDR-SECURITY-01 F1) — a read-scoped key is enough.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/themis-project/themis/internal/intelligence/app"
)

// RegistryClient walks the estate to list release ids.
type RegistryClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewRegistryClient builds the client against the Registry base URL (e.g. http://registry:8082).
func NewRegistryClient(baseURL string, hc *http.Client) *RegistryClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &RegistryClient{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// WithAPIKey makes every hop of the estate walk carry `X-API-Key` (EDR-SECURITY-01 F1). An empty
// key leaves the walk unauthenticated — the auth-off development case. A READ-ONLY key is enough.
//
// The walk aborts on the FIRST refused hop ("no releases, no work"), so on an auth-enabled
// Registry node an unauthenticated sweep finds no estate at all rather than part of one.
func (c *RegistryClient) WithAPIKey(apiKey string) *RegistryClient {
	c.apiKey = strings.TrimSpace(apiKey)
	return c
}

type idRow struct {
	ID string `json:"id"`
}

// ListReleaseIDs returns every release id across every product and project. A per-level read
// failure aborts (there is no partial estate worth sweeping); the caller (the sweep) treats the
// error as fatal, consistent with "no releases, no work".
func (c *RegistryClient) ListReleaseIDs(ctx context.Context) ([]string, error) {
	products, err := c.getIDs(ctx, "/api/v1/products")
	if err != nil {
		return nil, err
	}
	var releases []string
	for _, pid := range products {
		projects, perr := c.getIDs(ctx, "/api/v1/products/"+url.PathEscape(pid)+"/projects")
		if perr != nil {
			return nil, perr
		}
		for _, jid := range projects {
			rels, rerr := c.getIDs(ctx, "/api/v1/projects/"+url.PathEscape(jid)+"/releases")
			if rerr != nil {
				return nil, rerr
			}
			releases = append(releases, rels...)
		}
	}
	return releases, nil
}

func (c *RegistryClient) getIDs(ctx context.Context, path string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry: %s: status %d%s",
			path, resp.StatusCode, credentialHint(c.apiKey, resp.StatusCode, "Registry"))
	}
	var rows []idRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out, nil
}

var _ app.ReleaseLister = (*RegistryClient)(nil)
