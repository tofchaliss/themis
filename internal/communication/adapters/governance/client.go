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
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// Client calls Governance's read API to resolve a Finding's current Enterprise Position.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// defaultTimeout bounds one read-API call when the caller supplies no client of its own.
//
// http.DefaultClient has NO timeout, and these reads are no longer only on a request path: since
// N-M1b the remediation-ticket payload is rendered inside the inbox unit of work, so a Governance
// node that accepts a connection and then stalls would hold a bus-reader transaction open for as
// long as it liked. A bounded read turns that into a retried envelope.
//
// 30s rather than something tighter because a release posture is one query over every Finding of a
// Release; the bound exists to catch a stall, not to express an SLO.
const defaultTimeout = 30 * time.Second

// NewClient builds a client against the Governance base URL (e.g. "http://governance:8083").
// A nil http.Client falls back to one with defaultTimeout — never to http.DefaultClient, which
// would wait forever.
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{baseURL: baseURL, http: hc}
}

// WithAPIKey makes every read carry `X-API-Key` (the inbound-edge credential of EDR-SECURITY-01 F1).
// An empty key leaves the reads unauthenticated, which is the auth-off development case.
//
// Inter-service reads used to send no credential at all, on the reasoning that inbound-edge auth was
// for the estate's edge and reads were open between nodes. On an estate with `THEMIS_AUTH_REQUIRED=1`
// that is simply wrong: Governance answers 401, and the consequence is not a degraded read but a
// STUCK PIPELINE — since N-M1b the remediation-ticket payload is rendered from this read inside the
// inbox unit of work, so a 401 means no intent is recorded and the envelope is retried forever
// (measured on the enterprise VM, 2026-10-05). A READ-ONLY key is enough here; this client performs
// no write, and the key it is given should not be able to.
func (c *Client) WithAPIKey(apiKey string) *Client {
	c.apiKey = strings.TrimSpace(apiKey)
	return c
}

// newRequest builds one read-API GET, carrying the key when there is one. Every read in this client
// goes through it, so "does this seam authenticate" has one answer rather than three.
func (c *Client) newRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	return req, nil
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
	req, err := c.newRequest(ctx, url)
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
		return domain.PositionSnapshot{}, false,
			fmt.Errorf("governance read API: status %d%s", resp.StatusCode, c.credentialHint(resp.StatusCode))
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

// severityRow mirrors the two fields of the SAME release-posture JSON the remediation ticket
// consumes (N-M1b / RC-2). It is a second narrow view of one endpoint rather than a widened
// postureRow: the rollup needs the decided half and the occurrence verdicts, a ticket needs a
// CVE id and a number, and a struct serving both would tell a reader neither.
type severityRow struct {
	CVE       string `json:"cve"`
	BaseScore int    `json:"base_score"`
}

// ReleaseSeverity fetches the Release's posture reduced to the ticket's two facts. Implements
// app.ReleaseSeverityReader. A missing base_score decodes as 0, which the renderer reports as
// `Unknown` — never as `Low`.
func (c *Client) ReleaseSeverity(ctx context.Context, releaseID string) ([]app.ReleaseSeverityRow, error) {
	var rows []severityRow
	if err := c.getJSON(ctx, fmt.Sprintf("%s/api/v1/releases/%s/posture", c.baseURL, releaseID), &rows); err != nil {
		return nil, fmt.Errorf("governance: release severity %s: %w", releaseID, err)
	}
	out := make([]app.ReleaseSeverityRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, app.ReleaseSeverityRow{CVE: r.CVE, BaseScore: r.BaseScore})
	}
	return out, nil
}

// getJSON performs one read-API GET and decodes the body, or reports the status.
func (c *Client) getJSON(ctx context.Context, url string, into any) error {
	req, err := c.newRequest(ctx, url)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d%s", resp.StatusCode, c.credentialHint(resp.StatusCode))
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// credentialHint names the likely cause of a 401/403 in the error itself. The error reaches a bus
// reader's log and a delivery attempt's ledger, and on the enterprise VM "status 401" cost real time
// to trace back to an unset variable — the read looked broken rather than unauthenticated.
func (c *Client) credentialHint(status int) string {
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return ""
	}
	if c.apiKey == "" {
		return " — this read sent no X-API-Key; set THEMIS_API_KEY on this node (a read-scoped key is enough)"
	}
	return " — this read sent an X-API-Key Governance refused; check THEMIS_API_KEY is current and has read scope"
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
	var rows []postureRow
	if err := c.getJSON(ctx, fmt.Sprintf("%s/api/v1/releases/%s/posture", c.baseURL, releaseID), &rows); err != nil {
		return nil, fmt.Errorf("governance: release posture %s: %w", releaseID, err)
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
