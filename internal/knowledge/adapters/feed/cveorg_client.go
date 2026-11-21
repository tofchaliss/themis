package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// defaultCVEOrgBaseURL is the CVE Services API. GET /cve/<id> returns the CVE JSON 5 record, with
// no API key.
const defaultCVEOrgBaseURL = "https://cveawg.mitre.org/api"

// CVEOrgClient reads the CVE.org record of one CVE as a source revision (EDR-SCORING-01 S2,
// F13): the CNA container's ratings and each ADP container's, every CVSS version, each with its
// assessor. It implements app.CVERecordSource.
type CVEOrgClient struct {
	baseURL string
	http    *http.Client
}

// NewCVEOrgClient builds the client ("" → the public CVE Services API; nil → http.DefaultClient).
func NewCVEOrgClient(baseURL string, httpClient *http.Client) *CVEOrgClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultCVEOrgBaseURL
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &CVEOrgClient{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

var _ app.CVERecordSource = (*CVEOrgClient)(nil)

type cveOrgCVSS struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type cveOrgContainer struct {
	ProviderMetadata struct {
		OrgID       string `json:"orgId"`
		ShortName   string `json:"shortName"`
		DateUpdated string `json:"dateUpdated"`
	} `json:"providerMetadata"`
	Metrics []struct {
		V40 *cveOrgCVSS `json:"cvssV4_0"`
		V31 *cveOrgCVSS `json:"cvssV3_1"`
		V30 *cveOrgCVSS `json:"cvssV3_0"`
		V20 *cveOrgCVSS `json:"cvssV2_0"`
	} `json:"metrics"`
	Affected []struct {
		Vendor      string `json:"vendor"`
		Product     string `json:"product"`
		PackageName string `json:"packageName"`
	} `json:"affected"`
}

type cveOrgRecord struct {
	DataVersion string `json:"dataVersion"`
	CVEMetadata struct {
		CVEID       string `json:"cveId"`
		State       string `json:"state"`
		DateUpdated string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cveOrgContainer   `json:"cna"`
		ADP []cveOrgContainer `json:"adp"`
	} `json:"containers"`
}

// FetchRecord fetches and reads one record. 404 and a non-PUBLISHED record report found=false
// (a REJECTED CVE is a card-level event, outside this record, EDR 3.4 item 6).
func (c *CVEOrgClient) FetchRecord(ctx context.Context, cve value.CVEID) (domain.ObservationInput, bool, error) {
	endpoint := c.baseURL + "/cve/" + cve.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.ObservationInput{}, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.ObservationInput{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return domain.ObservationInput{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return domain.ObservationInput{}, false, fmt.Errorf("cveorg: GET cve/%s: status %d", cve.String(), resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return domain.ObservationInput{}, false, err
	}
	obs, ok, err := CVEOrgObservation(body)
	if err != nil {
		return domain.ObservationInput{}, false, fmt.Errorf("cveorg: %s: %w", cve.String(), err)
	}
	obs.Fetch = domain.FetchMeta{Endpoint: endpoint, HTTPStatus: resp.StatusCode, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	return obs, ok, nil
}

// CVEOrgObservation reads a CVE JSON 5 record. Exported for its test.
func CVEOrgObservation(body []byte) (domain.ObservationInput, bool, error) {
	var rec cveOrgRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return domain.ObservationInput{}, false, fmt.Errorf("invalid json: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(rec.CVEMetadata.State), "PUBLISHED") {
		return domain.ObservationInput{}, false, nil
	}
	obs := domain.ObservationInput{
		Source: "cveorg", Feed: "cve-services", DocumentRef: "cveorg:" + strings.TrimSpace(rec.CVEMetadata.CVEID),
		UpdatedAt: domain.ParseSourceTime(rec.CVEMetadata.DateUpdated), Complete: true,
	}
	for _, a := range rec.Containers.CNA.Affected {
		if s := cveOrgProduct(a.Vendor, a.Product, a.PackageName); s != "" {
			obs.Applicability = append(obs.Applicability, s)
		}
	}
	// The container a rating sits in is WHERE it was published, so it is the publisher: the
	// CNA container's assessor is the CVE's CNA (EDR 4.1 relationship table), which Governance
	// reads from this publisher value rather than guessing it from a name.
	obs.Ratings = append(obs.Ratings, cveOrgRatings(rec.Containers.CNA, CVEOrgPublisherCNA)...)
	for _, adp := range rec.Containers.ADP {
		obs.Ratings = append(obs.Ratings, cveOrgRatings(adp, CVEOrgPublisherADP)...)
	}
	return obs, true, nil
}

func cveOrgProduct(vendor, product, pkg string) string {
	parts := []string{}
	for _, s := range []string{vendor, product, pkg} {
		if s = strings.TrimSpace(s); s != "" && !strings.EqualFold(s, "n/a") {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ":")
}

// Publishers of CVE.org ratings: the record's CNA container and its ADP containers.
const (
	CVEOrgPublisherCNA = "cve.org/cna"
	CVEOrgPublisherADP = "cve.org/adp"
)

func cveOrgRatings(c cveOrgContainer, publisher string) []domain.PublishedRating {
	assessor := strings.TrimSpace(c.ProviderMetadata.ShortName)
	if assessor == "" {
		assessor = strings.TrimSpace(c.ProviderMetadata.OrgID)
	}
	var out []domain.PublishedRating
	for _, m := range c.Metrics {
		for _, x := range []struct {
			version string
			cvss    *cveOrgCVSS
		}{{"4.0", m.V40}, {"3.1", m.V31}, {"3.0", m.V30}, {"2.0", m.V20}} {
			if x.cvss == nil || strings.TrimSpace(x.cvss.VectorString) == "" || assessor == "" {
				continue
			}
			version := strings.TrimSpace(x.cvss.Version)
			if version == "" {
				version = x.version
			}
			out = append(out, domain.PublishedRating{
				Assessor: assessor, Publisher: publisher, Version: version, Vector: x.cvss.VectorString,
				StatedScore: x.cvss.BaseScore, HasStatedScore: true, SeverityWord: x.cvss.BaseSeverity,
			})
		}
	}
	return out
}
