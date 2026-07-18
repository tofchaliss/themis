package readapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// FaultlineClient reads a Faultline's enrichment from Knowledge's read API
// (GET /api/v1/faultlines/{id}). It implements app.FaultlineReader.
type FaultlineClient struct {
	baseURL string
	http    *http.Client
}

// NewFaultlineClient builds a client against the Knowledge base URL (e.g.
// "http://knowledge:8085"). A nil http.Client falls back to http.DefaultClient.
func NewFaultlineClient(baseURL string, hc *http.Client) *FaultlineClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &FaultlineClient{baseURL: baseURL, http: hc}
}

// wireFaultline mirrors Knowledge's FaultlineView + EnterpriseView JSON.
type wireFaultline struct {
	ID   string `json:"id"`
	CVE  string `json:"cve"`
	View struct {
		Severity       string   `json:"severity"`
		CVSSScore      float64  `json:"cvss_score"`
		EPSS           float64  `json:"epss"`
		KEV            bool     `json:"kev"`
		ExploitPublic  bool     `json:"exploit_public"`
		FixedVersions  []string `json:"fixed_versions"`
		AffectedRanges []string `json:"affected_ranges"`
	} `json:"view"`
}

// GetFaultline fetches the Faultline enrichment by id. A 404 yields a zero-value view
// (treated as incomplete grounding by Context Construction).
func (c *FaultlineClient) GetFaultline(ctx context.Context, faultlineID string) (domain.FaultlineView, error) {
	url := fmt.Sprintf("%s/api/v1/faultlines/%s", c.baseURL, faultlineID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.FaultlineView{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.FaultlineView{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return domain.FaultlineView{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return domain.FaultlineView{}, fmt.Errorf("knowledge read API: status %d", resp.StatusCode)
	}

	var wf wireFaultline
	if err := json.NewDecoder(resp.Body).Decode(&wf); err != nil {
		return domain.FaultlineView{}, err
	}
	return domain.FaultlineView{
		ID:             wf.ID,
		CVE:            wf.CVE,
		Severity:       wf.View.Severity,
		CVSSScore:      wf.View.CVSSScore,
		EPSS:           wf.View.EPSS,
		KEV:            wf.View.KEV,
		ExploitPublic:  wf.View.ExploitPublic,
		FixedVersions:  wf.View.FixedVersions,
		AffectedRanges: wf.View.AffectedRanges,
	}, nil
}
