// Package readapi holds the Intelligence Gateway's Knowledge Providers (D5): HTTP
// clients for the Governance and Knowledge read APIs. Each decodes wire JSON into the
// intelligence domain's own view types — never importing another context's packages
// (the JSON contract is the only coupling). They satisfy the app FindingReader /
// FaultlineReader ports.
package readapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// FindingClient reads the subject Finding from Governance's read API
// (GET /api/v1/findings/{id}). It implements app.FindingReader.
type FindingClient struct {
	baseURL string
	http    *http.Client
}

// NewFindingClient builds a client against the Governance base URL (e.g.
// "http://governance:8083"). A nil http.Client falls back to http.DefaultClient.
func NewFindingClient(baseURL string, hc *http.Client) *FindingClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &FindingClient{baseURL: baseURL, http: hc}
}

// wireFinding mirrors Governance's FindingView JSON (the read-API contract).
type wireFinding struct {
	ID          string          `json:"id"`
	ReleaseID   string          `json:"release_id"`
	FaultlineID string          `json:"faultline_id"`
	CVE         string          `json:"cve"`
	Stage       string          `json:"stage"`
	Components  []wireComponent `json:"components"`
}

type wireComponent struct {
	PURL string `json:"purl"`
}

// GetFinding fetches the Finding by id. A 404 yields a zero-value view (found=false
// at the domain layer, which Context Construction treats as incomplete grounding).
func (c *FindingClient) GetFinding(ctx context.Context, findingID string) (domain.FindingView, error) {
	url := fmt.Sprintf("%s/api/v1/findings/%s", c.baseURL, findingID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.FindingView{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.FindingView{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return domain.FindingView{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return domain.FindingView{}, fmt.Errorf("governance read API: status %d", resp.StatusCode)
	}

	var wf wireFinding
	if err := json.NewDecoder(resp.Body).Decode(&wf); err != nil {
		return domain.FindingView{}, err
	}
	purls := make([]string, 0, len(wf.Components))
	for _, comp := range wf.Components {
		if comp.PURL != "" {
			purls = append(purls, comp.PURL)
		}
	}
	return domain.FindingView{
		ID:          wf.ID,
		ReleaseID:   wf.ReleaseID,
		FaultlineID: wf.FaultlineID,
		CVE:         wf.CVE,
		Stage:       wf.Stage,
		Components:  purls,
	}, nil
}
