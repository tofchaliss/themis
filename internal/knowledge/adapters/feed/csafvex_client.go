package feed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// CSAFVexClient is the generic vendor CSAF-VEX feed (parity B4): for a CVE it fetches
// <base>/<year>/cve-<id>.json from each configured vendor base URL — the CSAF trusted-provider
// per-CVE VEX convention — parses the CSAF document, and folds each `not_affected` product as an
// applicability Proposal. Per-CVE (the sweep iterates already-carded CVEs) so it is
// relevance-bounded by construction (D5) — no bulk feed download. It implements app.VexFeedSource.
type CSAFVexClient struct {
	bases []string
	http  *http.Client
}

// NewCSAFVexClient builds the client over the given CSAF-VEX base URLs (each is a directory whose
// per-CVE files live at /<year>/cve-<id>.json) and HTTP client (nil → http.DefaultClient). Empty
// or blank base entries are dropped.
func NewCSAFVexClient(baseURLs []string, httpClient *http.Client) *CSAFVexClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	bases := make([]string, 0, len(baseURLs))
	for _, b := range baseURLs {
		if b = strings.TrimRight(strings.TrimSpace(b), "/"); b != "" {
			bases = append(bases, b)
		}
	}
	return &CSAFVexClient{bases: bases, http: httpClient}
}

var _ app.VexFeedSource = (*CSAFVexClient)(nil)

// FetchCVE fetches and translates one CVE's CSAF-VEX across every configured base. A base that
// 404s simply does not cover the CVE (no statements, no error); a base that errors (5xx /
// transport) is tried past, and its error is surfaced only if EVERY base errored (so the sweep
// skips the CVE rather than folding a partial view). An unparseable CVE argument is skipped.
func (c *CSAFVexClient) FetchCVE(ctx context.Context, cve string) ([]app.ProposalFor, error) {
	cveID, err := value.NewCVEID(cve)
	if err != nil {
		return nil, nil // a carded id that no longer parses — skip defensively
	}
	year := cveYear(cveID.String())
	if year == "" {
		return nil, nil
	}

	var out []app.ProposalFor
	var lastErr error
	reachedAny := false
	for _, base := range c.bases {
		url := base + "/" + year + "/" + strings.ToLower(cveID.String()) + ".json"
		stmts, ferr := c.fetchOne(ctx, url)
		if ferr != nil {
			lastErr = ferr
			continue // one vendor down — try the others
		}
		reachedAny = true
		for _, st := range stmts {
			p, perr := domain.NewApplicabilityProposal("vexfeed", st.ObservedAt, domain.Applicability{
				Package: st.Package, Status: "not_affected", Justification: st.Justification,
			})
			if perr == nil {
				out = append(out, app.ProposalFor{CVE: st.CVE, Proposal: p})
			}
		}
	}
	if !reachedAny && lastErr != nil {
		return nil, lastErr // every configured base errored — let the sweep skip this CVE
	}
	return out, nil
}

// fetchOne fetches and parses one CSAF-VEX document. A 404 (the vendor does not cover this CVE)
// returns no statements and no error; any other non-200 is a real error.
func (c *CSAFVexClient) fetchOne(ctx context.Context, url string) ([]csafStatement, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // this vendor has no VEX for this CVE — a normal gap
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vexfeed: GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseCSAFVEX(body)
}

// cveYear returns the year field of a canonical CVE id ("CVE-2024-1234" → "2024").
func cveYear(cve string) string {
	parts := strings.Split(cve, "-")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}
