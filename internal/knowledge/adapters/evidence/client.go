// Package evidence is the Knowledge context's client for Evidence's read API (D4): it
// reads a release's canonical inventory over HTTP and implements the app InventoryReader
// port. It never imports the Evidence context or touches its tables (Book III §3.5) —
// the two collaborate solely via the read API.
package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// Client reads inventories from an Evidence service.
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

type inventoryResponse struct {
	Components []struct {
		Purl      string `json:"purl"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		Source    string `json:"source"`
	} `json:"components"`
	// Dependencies carries Evidence's normalized relationship edges. Knowledge consumes ONLY
	// the ownership edges (`ownership-by-file-overlap` — Syft's file-overlap proof that one
	// package installed another's files): they are the Observed-grade evidence of the
	// EDR-VERDICT-01 D3 bridge. A depends_on edge is not ownership and is ignored here.
	Dependencies []struct {
		From         string `json:"from"`
		To           string `json:"to"`
		Relationship string `json:"relationship"`
	} `json:"dependencies"`
}

// GetInventory fetches the canonical inventory for an Evidence id via Evidence's read
// API and maps it into the Knowledge-local shape.
func (c *Client) GetInventory(ctx context.Context, evidenceID string) (app.Inventory, error) {
	url := c.baseURL + "/api/v1/evidence/" + evidenceID + "/inventory"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return app.Inventory{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return app.Inventory{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return app.Inventory{}, fmt.Errorf("evidence: inventory %s: status %d", evidenceID, resp.StatusCode)
	}

	var body inventoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return app.Inventory{}, err
	}
	inv := app.Inventory{Components: make([]app.InventoryComponent, 0, len(body.Components))}
	for _, comp := range body.Components {
		inv.Components = append(inv.Components, app.InventoryComponent{
			PURL: comp.Purl, Name: comp.Name, Version: comp.Version, Ecosystem: comp.Ecosystem, Source: comp.Source,
		})
	}
	for _, dep := range body.Dependencies {
		if dep.Relationship != "ownership-by-file-overlap" || dep.From == "" || dep.To == "" {
			continue
		}
		if inv.Owners == nil {
			inv.Owners = map[string]string{}
		}
		inv.Owners[dep.To] = dep.From // owned PURL -> owning PURL (the rpm)
	}
	return inv, nil
}

type documentResponse struct {
	Kind     string `json:"kind"`
	Document string `json:"document"`
}

// GetDocument fetches an evidence document's raw bytes + kind via Evidence's read API — the
// read path Knowledge uses to parse an uploaded VEX (EDR-VEX-01 D2/D6).
func (c *Client) GetDocument(ctx context.Context, evidenceID string) ([]byte, string, error) {
	url := c.baseURL + "/api/v1/evidence/" + evidenceID + "/document"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("evidence: document %s: status %d", evidenceID, resp.StatusCode)
	}
	var body documentResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, "", err
	}
	return []byte(body.Document), body.Kind, nil
}
