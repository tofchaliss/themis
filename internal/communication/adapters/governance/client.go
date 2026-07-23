// Package governance is the Communication context's client for Governance's read API (D2):
// it fetches an Enterprise Position (+ lineage) over HTTP via GET /findings/{id}, never
// Governance's tables and never importing Governance's packages — the JSON contract is the
// only coupling. It implements the app's PositionReader port.
package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/themis-project/themis/internal/communication/domain"
)

// Client calls Governance's read API to resolve a Finding's current Enterprise Position.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient builds a client against the Governance base URL (e.g. "http://governance:8083").
// A nil http.Client falls back to http.DefaultClient.
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: baseURL, http: hc}
}

// findingView mirrors Governance's FindingView JSON (the read-API contract).
type findingView struct {
	ID              string        `json:"id"`
	ReleaseID       string        `json:"release_id"`
	FaultlineID     string        `json:"faultline_id"`
	CVE             string        `json:"cve"`
	CurrentPosition *positionView `json:"current_position"`
}

type positionView struct {
	Version   int    `json:"version"`
	Stance    string `json:"stance"`
	Rationale string `json:"rationale"`
}

// GetPosition fetches the Finding's current Enterprise Position + lineage. found=false when
// the Finding is unknown (404) or has no current Position yet (no decision).
func (c *Client) GetPosition(ctx context.Context, findingID string) (domain.PositionSnapshot, bool, error) {
	url := fmt.Sprintf("%s/api/v1/findings/%s", c.baseURL, findingID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.PositionSnapshot{}, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.PositionSnapshot{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return domain.PositionSnapshot{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return domain.PositionSnapshot{}, false, fmt.Errorf("governance read API: status %d", resp.StatusCode)
	}

	var fv findingView
	if err := json.NewDecoder(resp.Body).Decode(&fv); err != nil {
		return domain.PositionSnapshot{}, false, err
	}
	if fv.CurrentPosition == nil {
		return domain.PositionSnapshot{}, false, nil // found, but not yet decided
	}
	return domain.PositionSnapshot{
		FindingID: findingID,
		Version:   fv.CurrentPosition.Version,
		Stance:    domain.Stance(fv.CurrentPosition.Stance),
		Rationale: fv.CurrentPosition.Rationale,
		Lineage: domain.Lineage{
			ReleaseID:   fv.ReleaseID,
			FindingID:   findingID,
			FaultlineID: fv.FaultlineID,
			CVE:         fv.CVE,
		},
	}, true, nil
}
