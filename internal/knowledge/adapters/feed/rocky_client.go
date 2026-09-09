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
					// Source packages only: "kernel-0:5.14...el9_8.cloud.1.0.src.rpm".
					if f, ok := rockyFixFromNVRA(nvra); ok {
						fixes = append(fixes, f)
					}
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

// VulnsForCVE returns the Rocky advisory fix bounds for ONE CVE (KN-MODULE-4). It implements
// app.CVEVulnSource so the existing BackfillService drives it — per-CVE, staleness-bounded and
// capped per sweep, the same D5a shape NVD uses.
//
// It exists because RLSA (Rocky's rebuild of a Red Hat advisory) is the only place a MODULAR
// package's fix is stated as a real build. Red Hat's CVE record gives the module stream NAME
// ("httpd:2.4-8040020211008164252.522a0ee4"), which bounds nothing; RLSA-2021:3816 gives
// "httpd-0:2.4.37-39.module+el8.4.0+571+fd70afb1", which an installed 2.4.37-65 clears exactly.
// Measured live 2026-09-09: without this, 17 httpd CVEs on a PATCHED el8.10 build stayed open,
// CVE-2021-40438 among them — critical, KEV, EPSS 0.99999, top of estate while not applicable.
//
// RLSA is an additional EVIDENCE SOURCE for fix bounds, never a second authority: the Proposals
// carry SeverityUnknown so `rocky` cannot take the severity headline (D11), and they create no
// applicability path of their own. Everything downstream — fold, precedence, RPMFixedByStream —
// is the existing machinery, unchanged.
//
// This method is deliberately THIN: query, select advisory classes, extract .src.rpm NVRAs,
// translate to FixedVersion. No version comparison, no stream reasoning, no applicability or
// severity decision, no dedup policy beyond what fold already provides. It is an adapter, not a
// verdict engine.
//
// A CVE Rocky does not track yields empty facts, not an error — the same "no data" contract the
// other per-CVE sources use.
func (c *RockyClient) VulnsForCVE(ctx context.Context, cve value.CVEID) (app.CVEFacts, error) {
	pg, err := c.fetchCVE(ctx, cve.String())
	if err != nil {
		return app.CVEFacts{}, err
	}
	var fixes []domain.FixedVersion
	seen := map[string]struct{}{}
	for _, adv := range pg.Advisories {
		if !rockyIsSecurityAdvisory(adv.Name) {
			continue
		}
		// The keyword search is fuzzy: it also returns advisories that merely MENTION the id.
		// Only an advisory that actually lists this CVE states a fix for it.
		if !rockyAdvisoryCovers(adv.Cves, cve) {
			continue
		}
		for _, product := range adv.Rpms {
			for _, nvra := range product.Nvras {
				f, ok := rockyFixFromNVRA(nvra)
				if !ok {
					continue
				}
				key := f.Package + "|" + f.Version
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				fixes = append(fixes, f)
			}
		}
	}
	if len(fixes) == 0 {
		return app.CVEFacts{}, nil // no Rocky record for this CVE — leave the card alone
	}
	// SeverityUnknown: `rocky` supplies fix BOUNDS, never a severity headline (D11). Rocky
	// never withdraws a CVE, so Withdrawn is always false here — an absent record is an
	// absence, not a retraction.
	p, err := domain.NewVulnFactsProposal("rocky", c.now().UTC(), domain.VulnFacts{
		Severity: value.SeverityUnknown, Fixes: fixes,
	})
	if err != nil {
		return app.CVEFacts{}, err
	}
	return app.CVEFacts{Proposal: app.ProposalFor{CVE: cve, Proposal: p}, Found: true}, nil
}

// rockyIsSecurityAdvisory keeps the security advisory classes and drops everything else the
// fuzzy keyword search returns — notably RLBA (bugfix) and RLEA (enhancement), which rebuild the
// same packages without stating a security fix.
func rockyIsSecurityAdvisory(name string) bool {
	n := strings.ToUpper(strings.TrimSpace(name))
	return strings.HasPrefix(n, "RLSA-") || strings.HasPrefix(n, "RXSA-")
}

// rockyAdvisoryCovers reports whether the advisory names this CVE.
func rockyAdvisoryCovers(cves []struct {
	Name string `json:"name"`
}, cve value.CVEID) bool {
	for _, cv := range cves {
		if id, err := value.NewCVEID(cv.Name); err == nil && id.String() == cve.String() {
			return true
		}
	}
	return false
}

// rockyFixFromNVRA translates one advisory NVRA into an attributed fix bound, or reports that it
// carries none. SOURCE packages only (the `.src.rpm` NVRAs): the binary-rpm list is the rebuild
// SCOPE (EDR-CORRELATION-01), not N fix claims, and correlation keys fixes by the source package.
// An NVRA naming no package is dropped — an unattributed fix can never decide (KN-FIX-1).
func rockyFixFromNVRA(nvra string) (domain.FixedVersion, bool) {
	nvra = strings.TrimSpace(nvra)
	if !strings.HasSuffix(nvra, ".src.rpm") {
		return domain.FixedVersion{}, false
	}
	v := strings.TrimSuffix(nvra, ".rpm")
	pkg := value.RPMPackageName(v)
	if pkg == "" {
		return domain.FixedVersion{}, false
	}
	return domain.FixedVersion{Package: pkg, Version: value.RPMEVR(v), Ecosystem: "rpm"}, true
}

// fetchCVE fetches the advisories the errata service matches for one CVE id. The estate's carded
// set is small and the per-CVE result tiny (3 advisories for CVE-2021-40438, measured
// 2026-09-09) — where the RLSA universe is 4103, which is why this is per-CVE and not a walk.
func (c *RockyClient) fetchCVE(ctx context.Context, cve string) (rockyAdvisoryPage, error) {
	q := url.Values{}
	q.Set("filters.keyword", cve)
	q.Set("page", "0")
	q.Set("limit", strconv.Itoa(rockyPageSize))
	return c.fetch(ctx, c.baseURL+"/api/v2/advisories?"+q.Encode(), "cve "+cve)
}

// fetchPage fetches one page of the RXSA keyword listing.
func (c *RockyClient) fetchPage(ctx context.Context, page int) (rockyAdvisoryPage, error) {
	q := url.Values{}
	q.Set("filters.keyword", "RXSA")
	q.Set("page", strconv.Itoa(page))
	q.Set("limit", strconv.Itoa(rockyPageSize))
	return c.fetch(ctx, c.baseURL+"/api/v2/advisories?"+q.Encode(), fmt.Sprintf("page %d", page))
}

// fetch performs one advisory-listing request. `what` names the request in errors so a failure
// says which listing failed.
func (c *RockyClient) fetch(ctx context.Context, reqURL, what string) (rockyAdvisoryPage, error) {
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
		return rockyAdvisoryPage{}, fmt.Errorf("rocky: GET advisories %s: status %d", what, resp.StatusCode)
	}
	var pg rockyAdvisoryPage
	if err := json.NewDecoder(resp.Body).Decode(&pg); err != nil {
		return rockyAdvisoryPage{}, fmt.Errorf("rocky: invalid json for %s: %w", what, err)
	}
	return pg, nil
}
