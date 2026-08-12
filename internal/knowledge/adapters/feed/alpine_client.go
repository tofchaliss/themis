package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// defaultAlpineBaseURL is the public Alpine security database — per-branch JSON files at
// /<branch>/{main,community}.json. It is the authoritative source Trivy/Grype/OSV themselves
// derive Alpine data from. No API key: public and unauthenticated.
const defaultAlpineBaseURL = "https://secdb.alpinelinux.org"

// alpineRepos are the secdb repository files per branch. Testing/community-edge exist upstream
// but ship no stable-branch files; main+community cover what an SBOM's apk PURLs can carry.
var alpineRepos = []string{"main", "community"}

// AlpineClient fetches Alpine secdb branch databases and translates them into fix-bound
// vuln-facts Proposals for already-carded CVEs (EDR-VEX-01 D7). The secdb is not per-CVE
// addressable, so the D5 relevance bound is applied HERE: the known set is consulted while
// walking the branch DB and every uncarded record is discarded in memory — enrichment of
// existing cards, never a mirror. It implements app.AlpineFixSource.
type AlpineClient struct {
	baseURL  string
	branches []string
	http     *http.Client
	now      func() time.Time
}

// NewAlpineClient builds the client over the given base URL ("" → the public secdb default),
// branch list (e.g. ["v3.18", "v3.19"]), and HTTP client (nil → http.DefaultClient).
func NewAlpineClient(baseURL string, branches []string, httpClient *http.Client) *AlpineClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultAlpineBaseURL
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &AlpineClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		branches: branches,
		http:     httpClient,
		now:      time.Now,
	}
}

var _ app.AlpineFixSource = (*AlpineClient)(nil)

// alpineSecDB is the subset of a secdb branch file the ACL consumes: each package's
// secfixes map fixed apk version → the security ids that version fixes.
type alpineSecDB struct {
	Packages []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

// ProposalsForKnown fetches every configured branch's main+community DBs and returns one
// `alpine` vuln-facts Proposal per carded CVE, carrying its fix bounds (package → fixed apk
// version, deduplicated across branches). Severity is SeverityUnknown throughout — the secdb
// states none, and the reconciled headline skips unknown, so the Proposal contributes bounds
// and nothing else. A 404 branch/repo is a normal gap (the branch is not published upstream);
// any other failure aborts the sweep so feed health records it and the next interval retries.
func (c *AlpineClient) ProposalsForKnown(ctx context.Context, known map[string]struct{}) ([]app.ProposalFor, error) {
	fixesByCVE := map[string][]domain.FixedVersion{}
	seen := map[string]struct{}{}
	for _, branch := range c.branches {
		branch = strings.TrimSpace(branch)
		if branch == "" {
			continue
		}
		for _, repo := range alpineRepos {
			db, found, err := c.fetchDB(ctx, branch, repo)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			for _, p := range db.Packages {
				name := strings.TrimSpace(p.Pkg.Name)
				if name == "" {
					continue
				}
				for fixVersion, ids := range p.Pkg.Secfixes {
					fixVersion = strings.TrimSpace(fixVersion)
					// "0" is the secdb's known-unfixed marker — a vulnerability list, not a bound.
					if fixVersion == "" || fixVersion == "0" {
						continue
					}
					for _, raw := range ids {
						// Entries mix CVEs with other ids (XSA-…, ZBX-…); some carry trailing
						// annotations. firstCVE folds what normalizes to a canonical CVE and
						// skips the rest — non-CVE ids can never match a card.
						cveID, cerr := firstCVE(strings.Fields(raw)...)
						if cerr != nil {
							continue
						}
						if _, carded := known[cveID.String()]; !carded {
							continue // the D5 bound: uncarded records are discarded here
						}
						key := cveID.String() + "|" + name + "|" + fixVersion
						if _, dup := seen[key]; dup {
							continue
						}
						seen[key] = struct{}{}
						fixesByCVE[cveID.String()] = append(fixesByCVE[cveID.String()],
							domain.FixedVersion{Package: name, Version: fixVersion})
					}
				}
			}
		}
	}

	observedAt := c.now().UTC()
	out := make([]app.ProposalFor, 0, len(fixesByCVE))
	for cveStr, fixes := range fixesByCVE {
		cveID, err := value.NewCVEID(cveStr)
		if err != nil {
			continue // keys came from canonical ids; skip defensively
		}
		p, err := domain.NewVulnFactsProposal("alpine", observedAt, domain.VulnFacts{
			Severity: value.SeverityUnknown, Fixes: fixes,
		})
		if err != nil {
			continue
		}
		out = append(out, app.ProposalFor{CVE: cveID, Proposal: p})
	}
	return out, nil
}

// fetchDB fetches one branch/repo secdb file. found=false on 404 (the branch is not published
// upstream — a configured-but-absent branch is a normal gap, not an error).
func (c *AlpineClient) fetchDB(ctx context.Context, branch, repo string) (alpineSecDB, bool, error) {
	url := c.baseURL + "/" + branch + "/" + repo + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return alpineSecDB{}, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return alpineSecDB{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return alpineSecDB{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return alpineSecDB{}, false, fmt.Errorf("alpine: GET %s/%s.json: status %d", branch, repo, resp.StatusCode)
	}
	var db alpineSecDB
	if err := json.NewDecoder(resp.Body).Decode(&db); err != nil {
		return alpineSecDB{}, false, fmt.Errorf("alpine: invalid json for %s/%s: %w", branch, repo, err)
	}
	return db, true, nil
}
