package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// NVDBaseURL is the default NVD 2.0 CVE API endpoint.
const NVDBaseURL = "https://services.nvd.nist.gov"

// nvdTimeLayout is NVD's timestamp format for lastModStartDate / lastModEndDate and the
// records' lastModified field (ISO-8601 with milliseconds, no zone).
const nvdTimeLayout = "2006-01-02T15:04:05.000"

// nvdPageSize is the NVD 2.0 max results per page; nvdMaxPages bounds a single poll so a
// wide window can never run away.
const (
	nvdPageSize = 2000
	nvdMaxPages = 10
)

// NVDClient is the real NVD **modified-since** feed-fetch client (EDR-KNOWLEDGE-01 D5):
// the scheduled watch pulls CVEs changed since a watermark and translates each into a
// vuln-facts Proposal via the NVD ACL. It implements app.ChangedVulnSource.
//
// It is where **CVSS v4.0** enters Knowledge (go-forward D-NVD-2): extractNVDCVSS reads
// cvssMetricV40 alongside v3.1/v3.0/v2, so a CVE NVD scored only under v4.0 carries a
// real severity/score instead of `unknown`.
type NVDClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
	acl     nvdACL
}

// NewNVDClient builds a client against the NVD base URL (default NVDBaseURL). An empty
// apiKey uses the lower unauthenticated rate limit; a nil http.Client falls back to
// http.DefaultClient.
func NewNVDClient(baseURL, apiKey string, hc *http.Client) *NVDClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = NVDBaseURL
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &NVDClient{baseURL: strings.TrimRight(baseURL, "/"), apiKey: strings.TrimSpace(apiKey), http: hc}
}

type nvdLiveResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdLiveCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdLiveCVE struct {
	ID             string      `json:"id"`
	LastModified   string      `json:"lastModified"`
	Metrics        nvdMetrics  `json:"metrics"`
	Configurations []nvdConfig `json:"configurations"`
}

type nvdConfig struct {
	Nodes []struct {
		CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	} `json:"nodes"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// nvdMetrics is NVD's per-version metric set. v4.0 is read (the D-NVD-2 fix); the v0.3.x
// monolith omitted it.
type nvdMetrics struct {
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V40 []nvdMetric `json:"cvssMetricV40"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

// nvdMetric is one CVSS metric entry. `type` is Primary (NVD analysts) or Secondary (the
// CNA); baseSeverity sits on cvssData for v3.x/v4.0 and at the top level for v2.
type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// ChangedSince pulls every CVE modified in [since, now] and translates it. CVEs NVD has
// not scored under any CVSS version are skipped (a scoreless vuln-facts Proposal would
// carry no signal); the watch's job is to fill severity/score.
func (c *NVDClient) ChangedSince(ctx context.Context, since time.Time) ([]app.ProposalFor, error) {
	end := time.Now().UTC()
	var out []app.ProposalFor
	startIndex := 0
	for page := 0; page < nvdMaxPages; page++ {
		resp, err := c.fetchPage(ctx, since.UTC(), end, startIndex)
		if err != nil {
			return out, err
		}
		for _, v := range resp.Vulnerabilities {
			pf, ok, terr := c.translate(v.CVE)
			if terr != nil || !ok {
				continue // no CVSS, or unparseable — skip; the watch is best-effort per record
			}
			out = append(out, pf)
		}
		startIndex += len(resp.Vulnerabilities)
		if len(resp.Vulnerabilities) == 0 || startIndex >= resp.TotalResults {
			break
		}
	}
	return out, nil
}

func (c *NVDClient) fetchPage(ctx context.Context, start, end time.Time, startIndex int) (nvdLiveResponse, error) {
	q := url.Values{}
	q.Set("lastModStartDate", start.Format(nvdTimeLayout))
	q.Set("lastModEndDate", end.Format(nvdTimeLayout))
	q.Set("resultsPerPage", fmt.Sprintf("%d", nvdPageSize))
	q.Set("startIndex", fmt.Sprintf("%d", startIndex))
	u := c.baseURL + "/rest/json/cves/2.0?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nvdLiveResponse{}, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nvdLiveResponse{}, fmt.Errorf("nvd modified-since: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nvdLiveResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return nvdLiveResponse{}, fmt.Errorf("nvd modified-since: status %d: %s", resp.StatusCode, truncateForError(data))
	}
	var parsed nvdLiveResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nvdLiveResponse{}, fmt.Errorf("nvd modified-since: decode: %w", err)
	}
	return parsed, nil
}

// translate maps one live NVD CVE onto the curated nvdRecord the NVD ACL consumes, so the
// single translation definition (the ACL) still owns the domain mapping. ok=false when
// the CVE has no CVSS metric under any version.
func (c *NVDClient) translate(cve nvdLiveCVE) (app.ProposalFor, bool, error) {
	severity, score, vector, found := extractNVDCVSS(cve.Metrics)
	if !found {
		return app.ProposalFor{}, false, nil
	}
	observed := parseNVDTime(cve.LastModified)
	affected, fixed := nvdVersionFacts(cve.Configurations)

	rec := nvdRecord{
		ID:           cve.ID,
		ObservedAt:   observed.Format(time.RFC3339),
		BaseScore:    score,
		VectorString: vector,
		BaseSeverity: severity,
		Affected:     affected,
		Fixed:        fixed,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return app.ProposalFor{}, false, err
	}
	translated, err := c.acl.Translate(raw)
	if err != nil {
		return app.ProposalFor{}, false, err
	}
	if len(translated) == 0 {
		return app.ProposalFor{}, false, nil
	}
	return app.ProposalFor{CVE: translated[0].CVE, Proposal: translated[0].Proposal}, true, nil
}

// extractNVDCVSS reads CVSS severity/score/vector in a fixed version precedence —
// **v3.1 → v3.0 → v4.0 → v2** — preferring a **Primary** (NVD) entry over a **Secondary**
// (CNA) within the chosen version. Adding v4.0 to the chain is the go-forward D-NVD-2 fix:
// a CVE scored only under CVSS 4.0 (e.g. CVE-2025-8869) now yields a real severity/score.
// v3.1 stays first for cross-fleet comparability; v4.0 is the fallback when it is the only
// score present. found=false means NVD carries no CVSS at all (awaiting analysis).
func extractNVDCVSS(m nvdMetrics) (severity string, score float64, vector string, found bool) {
	for _, group := range [][]nvdMetric{m.V31, m.V30, m.V40, m.V2} {
		if len(group) == 0 {
			continue
		}
		best := group[0]
		for _, e := range group {
			if strings.EqualFold(e.Type, "Primary") {
				best = e
				break
			}
		}
		sev := best.CVSSData.BaseSeverity
		if sev == "" {
			sev = best.BaseSeverity // v2 carries baseSeverity at the top level
		}
		return sev, best.CVSSData.BaseScore, best.CVSSData.VectorString, true
	}
	return "", 0, "", false
}

// nvdVersionFacts flattens the vulnerable CPE matches into human-readable affected ranges
// and fix versions (the fixed version = a versionEndExcluding bound).
func nvdVersionFacts(configs []nvdConfig) (affected, fixed []string) {
	seenRange := map[string]struct{}{}
	seenFix := map[string]struct{}{}
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				if r := cpeRange(m); r != "" {
					if _, ok := seenRange[r]; !ok {
						seenRange[r] = struct{}{}
						affected = append(affected, r)
					}
				}
				if m.VersionEndExcluding != "" {
					if _, ok := seenFix[m.VersionEndExcluding]; !ok {
						seenFix[m.VersionEndExcluding] = struct{}{}
						fixed = append(fixed, m.VersionEndExcluding)
					}
				}
			}
		}
	}
	return affected, fixed
}

// cpeRange renders a CPE match's version bounds as a range string.
func cpeRange(m nvdCPEMatch) string {
	var parts []string
	switch {
	case m.VersionStartIncluding != "":
		parts = append(parts, ">="+m.VersionStartIncluding)
	case m.VersionStartExcluding != "":
		parts = append(parts, ">"+m.VersionStartExcluding)
	}
	switch {
	case m.VersionEndExcluding != "":
		parts = append(parts, "<"+m.VersionEndExcluding)
	case m.VersionEndIncluding != "":
		parts = append(parts, "<="+m.VersionEndIncluding)
	}
	return strings.Join(parts, ",")
}

// parseNVDTime parses NVD's timestamp; an unparseable/empty value defaults to now so the
// Proposal always carries a valid observation time.
func parseNVDTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s != "" {
		if t, err := time.Parse(nvdTimeLayout, s); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// ensure the port is satisfied at compile time.
var _ app.ChangedVulnSource = (*NVDClient)(nil)
