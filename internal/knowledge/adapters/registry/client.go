// Package registry is the Knowledge context's client for Registry's read API (EDR-PSIRT-01
// P2): the walk products -> projects -> releases that tells the PSIRT early alert which product
// each release belongs to. It implements the app EstateProducts port, never imports the Registry
// context and never touches its tables (Book III §3.5).
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// Client reads the estate graph from a Registry service.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewClient builds a client against the Registry base URL (e.g. http://registry:8082).
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// WithAPIKey makes every read carry `X-API-Key` (EDR-SECURITY-01 F1); a read-scoped key is
// enough. Empty leaves the reads unauthenticated (auth-off development).
func (c *Client) WithAPIKey(apiKey string) *Client {
	c.apiKey = strings.TrimSpace(apiKey)
	return c
}

var _ app.EstateProducts = (*Client)(nil)

type idName struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ReleaseProducts walks the estate and maps every release to its product: one call for the
// products, one per product and one per project, never one per release. Any failure is an
// error, because a partial map would read as "no product matched".
func (c *Client) ReleaseProducts(ctx context.Context) (map[string]app.ProductRef, error) {
	var products []idName
	if err := c.get(ctx, "/api/v1/products", &products); err != nil {
		return nil, fmt.Errorf("registry: list products: %w", err)
	}
	out := map[string]app.ProductRef{}
	for _, p := range products {
		var projects []idName
		if err := c.get(ctx, "/api/v1/products/"+url.PathEscape(p.ID)+"/projects", &projects); err != nil {
			return nil, fmt.Errorf("registry: projects of %s: %w", p.ID, err)
		}
		for _, pj := range projects {
			var releases []idName
			if err := c.get(ctx, "/api/v1/projects/"+url.PathEscape(pj.ID)+"/releases", &releases); err != nil {
				return nil, fmt.Errorf("registry: releases of %s: %w", pj.ID, err)
			}
			for _, r := range releases {
				out[r.ID] = app.ProductRef{ID: p.ID, Name: p.Name}
			}
		}
	}
	return out, nil
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
		hint := ""
		switch {
		case resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden:
		case c.apiKey == "":
			hint = " — this read sent no X-API-Key; set THEMIS_API_KEY on this node (a read-scoped key is enough)"
		default:
			hint = " — this read sent an X-API-Key Registry refused; check THEMIS_API_KEY is current and has read scope"
		}
		return fmt.Errorf("status %d%s", resp.StatusCode, hint)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}
