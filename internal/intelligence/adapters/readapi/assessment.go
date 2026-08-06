package readapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// AssessmentClient fetches the FindingAssessment **Domain Projection** from Governance
// (GET /api/v1/findings/{id}/assessment). It implements app.ProjectionReader.
//
// This is the runtime's only business read, and it composes nothing: one business-named
// projection, produced by the context that owns the Finding Selection Type. The runtime does
// not know which contexts contributed to it (Governance's own aggregate plus Knowledge's read
// API, as it happens) and issues no follow-up reads to complete it.
//
// It replaces the pair of gathering clients that used to fetch a Finding from Governance and
// a Faultline from Knowledge and compose them here — which made the runtime a participant in
// business orchestration (EDR-TRUST-01 T10 rule 1).
type AssessmentClient struct {
	baseURL string
	http    *http.Client
}

// NewAssessmentClient builds a client against the Governance base URL (e.g.
// "http://governance:8083"). A nil http.Client falls back to http.DefaultClient.
func NewAssessmentClient(baseURL string, hc *http.Client) *AssessmentClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &AssessmentClient{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// assessmentResponse mirrors Governance's FindingAssessment wire shape.
type assessmentResponse struct {
	Finding struct {
		ID          string `json:"id"`
		ReleaseID   string `json:"release_id"`
		FaultlineID string `json:"faultline_id"`
		CVE         string `json:"cve"`
		Stage       string `json:"stage"`
		Components  []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	} `json:"finding"`
	Knowledge struct {
		FaultlineID    string   `json:"faultline_id"`
		CVE            string   `json:"cve"`
		Severity       string   `json:"severity"`
		CVSSScore      float64  `json:"cvss_score"`
		EPSS           float64  `json:"epss"`
		KEV            bool     `json:"kev"`
		ExploitPublic  bool     `json:"exploit_public"`
		AffectedRanges []string `json:"affected_ranges"`
		FixedVersions  []string `json:"fixed_versions"`
	} `json:"knowledge"`
}

// GetAssessment fetches the projection for one Finding.
func (c *AssessmentClient) GetAssessment(ctx context.Context, findingID string) (domain.FindingAssessment, error) {
	url := c.baseURL + "/api/v1/findings/" + findingID + "/assessment"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.FindingAssessment{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.FindingAssessment{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return domain.FindingAssessment{}, fmt.Errorf("readapi: assessment %s: status %d", findingID, resp.StatusCode)
	}
	var body assessmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.FindingAssessment{}, err
	}

	purls := make([]string, 0, len(body.Finding.Components))
	for _, comp := range body.Finding.Components {
		purls = append(purls, comp.PURL)
	}
	return domain.FindingAssessment{
		Finding: domain.FindingView{
			ID: body.Finding.ID, ReleaseID: body.Finding.ReleaseID,
			FaultlineID: body.Finding.FaultlineID, CVE: body.Finding.CVE,
			Stage: body.Finding.Stage, Components: purls,
		},
		Knowledge: domain.FaultlineView{
			ID: body.Knowledge.FaultlineID, CVE: body.Knowledge.CVE,
			Severity: body.Knowledge.Severity, CVSSScore: body.Knowledge.CVSSScore,
			EPSS: body.Knowledge.EPSS, KEV: body.Knowledge.KEV,
			ExploitPublic:  body.Knowledge.ExploitPublic,
			AffectedRanges: body.Knowledge.AffectedRanges,
			FixedVersions:  body.Knowledge.FixedVersions,
		},
	}, nil
}
