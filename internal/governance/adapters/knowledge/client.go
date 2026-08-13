// Package knowledge is the Governance context's client for Knowledge's Faultline read API.
// It reads a CVE card's reconciled enrichment over HTTP and implements the app
// FaultlineKnowledgeReader port, so the FindingAssessment Domain Projection (EDR-TRUST-01
// T10) can carry what is known about the CVE alongside the Finding.
//
// It never imports the Knowledge context or touches its tables (Book III §3.5) — the two
// collaborate solely via events and this read API.
package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Client reads Faultline enrichment from a Knowledge service.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient builds a client against the Knowledge base URL (e.g. http://knowledge:8085).
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// faultlineResponse mirrors Knowledge's FaultlineView wire shape. Governance decodes into
// its own types rather than importing Knowledge's.
type faultlineResponse struct {
	ID   string `json:"id"`
	CVE  string `json:"cve"`
	View struct {
		Severity       string   `json:"severity"`
		Summary        string   `json:"summary"`
		CVSSScore      float64  `json:"cvss_score"`
		EPSS           float64  `json:"epss"`
		KEV            bool     `json:"kev"`
		ExploitPublic  bool     `json:"exploit_public"`
		AffectedRanges []string `json:"affected_ranges"`
		FixedVersions  []string `json:"fixed_versions"`
		// Fixes is the PACKAGE-ATTRIBUTED form of the same data (KN-FIX-1). `fixed_versions`
		// is a flat union across every package the CVE affects, so it cannot answer "what do I
		// upgrade THIS component to" — reading it produced a recommendation citing another
		// package's version (AI-GROUND-1).
		Fixes []struct {
			Package   string `json:"package"`
			Version   string `json:"version"`
			Ecosystem string `json:"ecosystem"` // absent = source did not say → filters nothing
		} `json:"fixes"`
		RangeTrust string `json:"range_trust"`
	} `json:"view"`
}

// GetFaultline fetches a Faultline's reconciled enrichment.
func (c *Client) GetFaultline(ctx context.Context, faultlineID string) (app.FaultlineKnowledge, error) {
	url := c.baseURL + "/api/v1/faultlines/" + faultlineID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return app.FaultlineKnowledge{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return app.FaultlineKnowledge{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return app.FaultlineKnowledge{}, fmt.Errorf("knowledge: faultline %s: status %d", faultlineID, resp.StatusCode)
	}
	var body faultlineResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return app.FaultlineKnowledge{}, err
	}
	fixes := make([]app.FixedVersion, 0, len(body.View.Fixes))
	for _, f := range body.View.Fixes {
		fixes = append(fixes, app.FixedVersion{Package: f.Package, Version: f.Version, Ecosystem: f.Ecosystem})
	}
	return app.FaultlineKnowledge{
		FaultlineID:    body.ID,
		CVE:            body.CVE,
		Summary:        body.View.Summary,
		Severity:       body.View.Severity,
		CVSSScore:      body.View.CVSSScore,
		EPSS:           body.View.EPSS,
		KEV:            body.View.KEV,
		ExploitPublic:  body.View.ExploitPublic,
		AffectedRanges: body.View.AffectedRanges,
		FixedVersions:  body.View.FixedVersions,
		Fixes:          fixes,
		RangeTrust:     value.TrustClass(body.View.RangeTrust),
	}, nil
}
