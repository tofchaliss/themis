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
			PURL       string `json:"purl"`
			ClaimClass string `json:"claim_class"`
		} `json:"components"`
	} `json:"finding"`
	Knowledge struct {
		FaultlineID       string   `json:"faultline_id"`
		CVE               string   `json:"cve"`
		Summary           string   `json:"summary"`
		Severity          string   `json:"severity"`
		CVSSScore         float64  `json:"cvss_score"`
		EPSS              float64  `json:"epss"`
		KEV               bool     `json:"kev"`
		ExploitPublic     bool     `json:"exploit_public"`
		AffectedRanges    []string `json:"affected_ranges"`
		FixedVersions     []string `json:"fixed_versions"`
		UnattributedFixes int      `json:"unattributed_fixes"`
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
	claims := make([]string, 0, len(body.Finding.Components))
	for _, comp := range body.Finding.Components {
		purls = append(purls, comp.PURL)
		claims = append(claims, comp.ClaimClass)
	}
	return domain.FindingAssessment{
		Finding: domain.FindingView{
			ID: body.Finding.ID, ReleaseID: body.Finding.ReleaseID,
			FaultlineID: body.Finding.FaultlineID, CVE: body.Finding.CVE,
			Stage: body.Finding.Stage, Components: purls, ClaimClasses: claims,
		},
		Knowledge: domain.FaultlineView{
			ID: body.Knowledge.FaultlineID, CVE: body.Knowledge.CVE,
			Summary:  body.Knowledge.Summary,
			Severity: body.Knowledge.Severity, CVSSScore: body.Knowledge.CVSSScore,
			EPSS: body.Knowledge.EPSS, KEV: body.Knowledge.KEV,
			ExploitPublic:     body.Knowledge.ExploitPublic,
			AffectedRanges:    body.Knowledge.AffectedRanges,
			FixedVersions:     body.Knowledge.FixedVersions,
			UnattributedFixes: body.Knowledge.UnattributedFixes,
		},
	}, nil
}

// posturePayload mirrors Governance's release-posture wire shape.
type posturePayload struct {
	FindingID         string `json:"finding_id"`
	CVE               string `json:"cve"`
	Stance            string `json:"stance"`
	ResidualPriority  int    `json:"residual_priority"`
	EffectivePriority int    `json:"effective_priority"`
	Components        []struct {
		PURL       string `json:"purl"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		Ecosystem  string `json:"ecosystem"`
		Source     string `json:"source"`
		ClaimClass string `json:"claim_class"`
		// VerdictState — `cleared_vendor_fix` means these files already carry the vendor's fix
		// (EDR-VERDICT-01 D8); absent on rows predating the field, which reads as open.
		VerdictState string `json:"verdict_state"`
	} `json:"components"`
	// Fixes are the versions published for THIS Finding's own components (PLAN-3). The runtime
	// decodes them for ONE reason (EDR-CORRELATION-01 D8 step 1): a distro module-stream fix
	// carries a build marker (`.module+el8.4.0+570+c2eaf144`), which is the only signal in the
	// projection that several packages are one `dnf module update` rather than several jobs.
	//
	// It does NOT make them upgrade targets in the prompt. The plan still never states a fix
	// version, because a model told a version is a target will recommend upgrading to the build
	// already installed.
	Fixes []struct {
		Package string `json:"package"`
		Version string `json:"version"`
	} `json:"fixes"`
}

// GetReleasePosture fetches the release-scoped Domain Projection from Governance
// (GET /api/v1/releases/{id}/posture) — every Finding on the Release with its priority and
// components, produced by the context that owns the Release's security view.
//
// One read, like the Finding projection beside it: the runtime does not fetch per-Finding detail
// to complete it, which is exactly the orchestration T10 rule 1 forbids. Anything the plan needs
// and the posture lacks is a gap in the projection, to be closed in Governance where a dashboard
// benefits equally — not patched here with a second call.
func (c *AssessmentClient) GetReleasePosture(ctx context.Context, releaseID string) (domain.ReleasePosture, error) {
	url := c.baseURL + "/api/v1/releases/" + releaseID + "/posture"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.ReleasePosture{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.ReleasePosture{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return domain.ReleasePosture{}, fmt.Errorf("governance: release posture %s: status %d", releaseID, resp.StatusCode)
	}
	var body []posturePayload
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.ReleasePosture{}, err
	}

	out := domain.ReleasePosture{ReleaseID: releaseID, Entries: make([]domain.PostureEntry, 0, len(body))}
	for _, e := range body {
		out.Entries = append(out.Entries, toPostureEntry(e))
	}
	return out, nil
}

// toPostureEntry maps one wire posture row to the domain shape — shared by the posture read
// and the comparison read, whose buckets are the same rows.
func toPostureEntry(e posturePayload) domain.PostureEntry {
	entry := domain.PostureEntry{
		FindingID: e.FindingID, CVE: e.CVE, Stance: e.Stance,
		ResidualPriority: e.ResidualPriority, EffectivePriority: e.EffectivePriority,
	}
	for _, c := range e.Components {
		entry.Components = append(entry.Components, domain.PostureComponent{
			PURL: c.PURL, Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, Source: c.Source,
			ClaimClass: c.ClaimClass, VerdictState: c.VerdictState,
		})
	}
	for _, f := range e.Fixes {
		entry.Fixes = append(entry.Fixes, domain.PostureFix{Package: f.Package, Version: f.Version})
	}
	return entry
}

// comparisonPayload mirrors Governance's ReleaseComparison wire shape (EDR-GOVERNANCE-01 D16).
type comparisonPayload struct {
	BaselineReleaseID  string           `json:"baseline_release_id"`
	CandidateReleaseID string           `json:"candidate_release_id"`
	Fixed              []posturePayload `json:"fixed"`
	New                []posturePayload `json:"new"`
	Persisting         []posturePayload `json:"persisting"`
}

// GetReleaseComparison fetches the cross-release diff from Governance
// (GET /api/v1/releases/{baseline}/compare/{candidate}) for compare_releases@v1 (AI-CMP-1).
// One read, buckets and ordering decided server-side (T10). Governance's honesty guard rides
// along: a 422 (a side has no evidence) or 502 (Evidence unreachable) surfaces as an error —
// the gateway turns it into an honest no-grounding outcome rather than narrating around it.
func (c *AssessmentClient) GetReleaseComparison(ctx context.Context, baselineID, candidateID string) (domain.ReleaseComparison, error) {
	url := c.baseURL + "/api/v1/releases/" + baselineID + "/compare/" + candidateID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.ReleaseComparison{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.ReleaseComparison{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return domain.ReleaseComparison{}, fmt.Errorf("governance: compare %s vs %s: status %d", baselineID, candidateID, resp.StatusCode)
	}
	var body comparisonPayload
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return domain.ReleaseComparison{}, err
	}
	out := domain.ReleaseComparison{BaselineID: body.BaselineReleaseID, CandidateID: body.CandidateReleaseID}
	for _, e := range body.Fixed {
		out.Fixed = append(out.Fixed, toPostureEntry(e))
	}
	for _, e := range body.New {
		out.New = append(out.New, toPostureEntry(e))
	}
	for _, e := range body.Persisting {
		out.Persisting = append(out.Persisting, toPostureEntry(e))
	}
	return out, nil
}
