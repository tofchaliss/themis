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
	"strings"

	"github.com/themis-project/themis/internal/communication/app"
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
	ID              string         `json:"id"`
	ReleaseID       string         `json:"release_id"`
	FaultlineID     string         `json:"faultline_id"`
	CVE             string         `json:"cve"`
	Components      []componentRef `json:"components"`
	CurrentPosition *positionView  `json:"current_position"`
}

// componentRef is the one field of Governance's Component this context needs: the PURL, which
// is the identifier every VEX/SBOM consumer resolves against.
type componentRef struct {
	PURL string `json:"purl"`
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
			Components:  purls(fv.Components),
		},
	}, true, nil
}

// purls extracts the component PURLs, skipping any blank one so an empty entry never becomes
// an empty OpenVEX subcomponent id.
func purls(cs []componentRef) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		if p := strings.TrimSpace(c.PURL); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// postureRow mirrors the fields of Governance's release-posture JSON the rollup consumes
// (EDR-COMMUNICATION-01 D13.5): the decided half (stance, position version + rationale) and
// the components with their occurrence-verdict fields.
type postureRow struct {
	FindingID         string `json:"finding_id"`
	FaultlineID       string `json:"faultline_id"`
	CVE               string `json:"cve"`
	Stance            string `json:"stance"`
	HasPosition       bool   `json:"has_position"`
	PositionVersion   int    `json:"position_version"`
	PositionRationale string `json:"position_rationale"`
	Components        []struct {
		PURL          string `json:"purl"`
		ClaimClass    string `json:"claim_class"`
		VerdictState  string `json:"verdict_state"`
		VerdictGrade  string `json:"verdict_grade"`
		VerdictReason string `json:"verdict_reason"`
	} `json:"components"`
}

// ReleasePosture fetches the release-scoped Domain Projection — the rollup's first read
// (D13.5). Implements app.ReleasePostureReader.
func (c *Client) ReleasePosture(ctx context.Context, releaseID string) ([]app.RollupPostureRow, error) {
	url := fmt.Sprintf("%s/api/v1/releases/%s/posture", c.baseURL, releaseID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("governance: release posture %s: status %d", releaseID, resp.StatusCode)
	}
	var rows []postureRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	out := make([]app.RollupPostureRow, 0, len(rows))
	for _, r := range rows {
		row := app.RollupPostureRow{
			FindingID: r.FindingID, FaultlineID: r.FaultlineID, CVE: r.CVE,
			HasPosition: r.HasPosition, Stance: r.Stance,
			PositionVersion: r.PositionVersion, PositionRationale: r.PositionRationale,
		}
		for _, comp := range r.Components {
			row.Components = append(row.Components, app.RollupComponentRow{
				PURL: comp.PURL, ClaimClass: comp.ClaimClass,
				VerdictState: comp.VerdictState, VerdictGrade: comp.VerdictGrade, VerdictReason: comp.VerdictReason,
			})
		}
		out = append(out, row)
	}
	return out, nil
}
