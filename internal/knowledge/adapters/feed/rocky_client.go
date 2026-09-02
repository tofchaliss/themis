package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// defaultRockyBaseURL is the public Rocky Linux errata service (Apollo). No API key.
const defaultRockyBaseURL = "https://errata.rockylinux.org"

// rockyPageSize is the advisories-per-page for the RXSA walk. The whole RXSA universe measured
// 29 advisories (2026-08-27), so the walk is normally a single request.
const rockyPageSize = 100

// rockyMaxPages hard-caps the pagination walk. It exists so a pathological `total` from the
// server can never turn one sweep into an unbounded crawl; at 100 per page it still allows two
// orders of magnitude above the measured universe.
const rockyMaxPages = 50

// RockyClient fetches Rocky RXSA errata and translates them into fix-bound vuln-facts
// Proposals for already-carded CVEs (EDR-VEX-01 D11). RXSA advisories cover Rocky-exclusive /
// SIG packages absent from Red Hat data; RLSA clones are excluded — their content already
// arrives via the Red Hat feed. The D5 relevance bound is applied HERE: the known set is
// consulted while walking the advisory list and every uncarded record is discarded in memory.
// It implements app.RockyFixSource.
type RockyClient struct {
	baseURL string
	http    *http.Client
	now     func() time.Time
}

// NewRockyClient builds the client over the given base URL ("" → the public errata service)
// and HTTP client (nil → http.DefaultClient).
func NewRockyClient(baseURL string, httpClient *http.Client) *RockyClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultRockyBaseURL
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &RockyClient{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient, now: time.Now}
}

var _ app.RockyFixSource = (*RockyClient)(nil)

// rockyAdvisoryPage is the subset of an Apollo v2 advisory listing the ACL consumes.
type rockyAdvisoryPage struct {
	Advisories []struct {
		Name string `json:"name"`
		Cves []struct {
			Name string `json:"name"`
		} `json:"cves"`
		Rpms map[string]struct {
			Nvras []string `json:"nvras"`
		} `json:"rpms"`
	} `json:"advisories"`
	Total int `json:"total"`
}

// ProposalsForKnown walks the RXSA advisories and returns one `rocky` vuln-facts Proposal per
// carded CVE, carrying its fix bounds. Bounds come from the SOURCE packages only (the
// `.src.rpm` NVRAs): the binary-rpm list is the rebuild SCOPE (EDR-CORRELATION-01), not N fix
// claims, and correlation keys fixes by the source package. Severity is SeverityUnknown
// throughout — `rocky` never contends for the headline (D11). Any page failure aborts the
// sweep so feed health records it and the next interval retries.
func (c *RockyClient) ProposalsForKnown(ctx context.Context, known map[string]struct{}) ([]app.ProposalFor, error) {
	fixesByCVE := map[string][]domain.FixedVersion{}
	seen := map[string]struct{}{}
	for page := 0; page < rockyMaxPages; page++ {
		pg, err := c.fetchPage(ctx, page)
		if err != nil {
			return nil, err
		}
		for _, adv := range pg.Advisories {
			// The keyword filter is a search, not a contract — the name prefix is (RLSA clones
			// and any fuzzy keyword hits are excluded here).
			if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(adv.Name)), "RXSA-") {
				continue
			}
			var fixes []domain.FixedVersion
			for _, product := range adv.Rpms {
				for _, nvra := range product.Nvras {
					nvra = strings.TrimSpace(nvra)
					// Source packages only: "kernel-0:5.14...el9_8.cloud.1.0.src.rpm".
					if !strings.HasSuffix(nvra, ".src.rpm") {
						continue
					}
					v := strings.TrimSuffix(nvra, ".rpm")
					pkg := value.RPMPackageName(v)
					if pkg == "" {
						continue // a bare EVR names no package and can never attribute (KN-FIX-1)
					}
					fixes = append(fixes, domain.FixedVersion{Package: pkg, Version: value.RPMEVR(v), Ecosystem: "rpm"})
				}
			}
			if len(fixes) == 0 {
				continue
			}
			for _, cv := range adv.Cves {
				cve, err := value.NewCVEID(cv.Name)
				if err != nil {
					continue
				}
				if _, carded := known[cve.String()]; !carded {
					continue // the D5 bound: uncarded records are discarded here
				}
				for _, f := range fixes {
					key := cve.String() + "|" + f.Package + "|" + f.Version
					if _, dup := seen[key]; dup {
						continue
					}
					seen[key] = struct{}{}
					fixesByCVE[cve.String()] = append(fixesByCVE[cve.String()], f)
				}
			}
		}
		if (page+1)*rockyPageSize >= pg.Total {
			break
		}
	}

	observedAt := c.now().UTC()
	out := make([]app.ProposalFor, 0, len(fixesByCVE))
	for cveStr, fixes := range fixesByCVE {
		cveID, err := value.NewCVEID(cveStr)
		if err != nil {
			continue // keys came from canonical ids; skip defensively
		}
		p, err := domain.NewVulnFactsProposal("rocky", observedAt, domain.VulnFacts{
			Severity: value.SeverityUnknown, Fixes: fixes,
		})
		if err != nil {
			continue
		}
		out = append(out, app.ProposalFor{CVE: cveID, Proposal: p})
	}
	return out, nil
}

// fetchPage fetches one page of the RXSA keyword listing.
func (c *RockyClient) fetchPage(ctx context.Context, page int) (rockyAdvisoryPage, error) {
	q := url.Values{}
	q.Set("filters.keyword", "RXSA")
	q.Set("page", strconv.Itoa(page))
	q.Set("limit", strconv.Itoa(rockyPageSize))
	reqURL := c.baseURL + "/api/v2/advisories?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return rockyAdvisoryPage{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return rockyAdvisoryPage{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return rockyAdvisoryPage{}, fmt.Errorf("rocky: GET advisories page %d: status %d", page, resp.StatusCode)
	}
	var pg rockyAdvisoryPage
	if err := json.NewDecoder(resp.Body).Decode(&pg); err != nil {
		return rockyAdvisoryPage{}, fmt.Errorf("rocky: invalid json for page %d: %w", page, err)
	}
	return pg, nil
}
