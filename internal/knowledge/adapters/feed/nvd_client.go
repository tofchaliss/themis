package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// NVDBaseURL is the default NVD 2.0 CVE API endpoint.
const NVDBaseURL = "https://services.nvd.nist.gov"

// nvdTimeLayout is NVD's timestamp format for lastModStartDate / lastModEndDate and the
// records' lastModified field (ISO-8601 with milliseconds, no zone).
const nvdTimeLayout = "2006-01-02T15:04:05.000"

// nvdPageSize is the NVD 2.0 max results per page; nvdMaxPages bounds a single SLICE so one
// request burst can never run away.
const (
	nvdPageSize = 2000
	nvdMaxPages = 10
)

// nvdSliceWindow is the initial width of one modified-since slice, and nvdMinSlice the
// narrowest a slice may be halved to before the poll gives up.
//
// The window since the watermark is walked in slices rather than requested whole, because a
// wide window holds far more records than the page budget can read. Measured against the live
// API on 2026-08-06, a 120-day window held **356,223** modified CVEs against a 20,000-record
// budget — so the previous whole-window request read 5.6% of it, stopped, and reported success
// (NVD-WATCH-1). Slicing keeps every request bounded while still covering the window, and a
// slice that overflows anyway is halved, so a burst of NVD activity self-corrects instead of
// depending on a tuned constant.
const (
	nvdSliceWindow = 24 * time.Hour
	nvdMinSlice    = time.Hour
)

// ErrWindowTruncated reports that a modified-since slice held more records than the page
// budget could read even at nvdMinSlice. It is returned WITH whatever was read so far, and it
// is deliberately an error rather than a silent short read: the caller's watermark advances
// only on success, so an unreadable slice is retried next poll instead of being skipped
// forever. Feed health degrades on it, which is the point — a feed that cannot see its window
// must not report healthy.
var ErrWindowTruncated = errors.New("nvd: modified-since slice exceeds the page budget")

// nvdMaxWindow is NVD's maximum lastModStartDate..lastModEndDate span (120 days). A zero
// watermark (first poll) would otherwise request the entire history; the start is clamped
// to it so the first pass covers the last 120 days of changes.
const nvdMaxWindow = 120 * 24 * time.Hour

// nvdMaxWalkPerPoll bounds how much of the backlog ONE poll covers, and nvdColdStartWindow how
// far back a poll reaches when there is no watermark at all.
//
// Both exist because NVD pages are slow, not because of any rate limit. Measured against the
// live API on 2026-08-07: a single 24-hour slice returned 5.2 MB and took **83.6 seconds** —
// server-side generation, with the next nine requests answering in ~1.2s each, so throttling
// was not involved. A 120-day cold start is therefore ~2.8 HOURS of walking, which no timeout
// or pacing tuning makes viable; the volume is the problem.
//
// Bounding the walk keeps each poll finite while staying lossless: ChangedSince reports the
// instant it covered, the watermark advances only that far, and the next poll resumes there.
// A long backlog drains over several polls instead of failing forever on the first.
//
// The real answer is to stop walking the window at all and fetch the ~hundreds of CARDED CVEs
// by id — cost proportional to the estate rather than to NVD's churn. That is a change to
// EDR-KNOWLEDGE-01 D5's relevance bound and is tracked as the open decision on NVD-WATCH-1.
const (
	nvdMaxWalkPerPoll  = 3 * 24 * time.Hour
	nvdColdStartWindow = 7 * 24 * time.Hour
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

	// Request pacing. NVD rate-limits per rolling 30 seconds — 5 requests unauthenticated, 50
	// with an API key — and throttled requests slow down rather than fail fast, so an unpaced
	// burst eventually exceeds the client timeout and takes the whole poll down.
	//
	// This did not matter until slicing arrived: the old whole-window fetch was capped at
	// nvdMaxPages, so a poll made at most 10 requests and the truncation that made it wrong
	// was ALSO, accidentally, keeping it inside the rate limit. Walking a 120-day window in
	// 24-hour slices makes a few hundred requests, which NVD will not serve back-to-back.
	mu      sync.Mutex
	minGap  time.Duration
	lastReq time.Time
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
	key := strings.TrimSpace(apiKey)
	return &NVDClient{
		baseURL: strings.TrimRight(baseURL, "/"), apiKey: key, http: hc,
		minGap: nvdMinRequestGap(key, baseURL),
	}
}

// nvdMinRequestGap is the minimum spacing between requests, derived from NVD's published rolling
// 30-second budget with a margin: 50 requests with a key, 5 without. Deriving it from the key
// rather than exposing a knob keeps pacing correct by construction — an operator cannot set a
// value that gets their deployment throttled.
//
// It applies ONLY to the public NVD endpoint. The budget is a property of that service, not of
// the protocol, so a self-hosted mirror or a test server is not paced — which also keeps the
// suite fast without any test having to know pacing exists.
func nvdMinRequestGap(apiKey, baseURL string) time.Duration {
	if strings.TrimRight(strings.TrimSpace(baseURL), "/") != NVDBaseURL {
		return 0
	}
	if apiKey != "" {
		return 700 * time.Millisecond // ~43 req / 30s, under the 50 budget
	}
	return 6500 * time.Millisecond // ~4.6 req / 30s, under the 5 budget
}

// NVDRequestGapForTest exposes the pacing policy to the package's external test.
func NVDRequestGapForTest(apiKey, baseURL string) time.Duration {
	return nvdMinRequestGap(apiKey, baseURL)
}

// pace blocks until the minimum gap since the previous request has elapsed. It honors context
// cancellation, so a shutdown or a timeout during a long walk aborts promptly instead of
// sleeping through it.
func (c *NVDClient) pace(ctx context.Context) error {
	c.mu.Lock()
	wait := time.Duration(0)
	now := time.Now()
	if !c.lastReq.IsZero() {
		if elapsed := now.Sub(c.lastReq); elapsed < c.minGap {
			wait = c.minGap - elapsed
		}
	}
	c.lastReq = now.Add(wait)
	c.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type nvdLiveResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdLiveCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdLiveCVE struct {
	ID           string `json:"id"`
	LastModified string `json:"lastModified"`
	// VulnStatus is NVD's analysis state. "Rejected" means the CVE was withdrawn upstream —
	// the signal that retires a card (KN-WITHDRAW-1). It was in every response all along and
	// read by nothing.
	VulnStatus     string      `json:"vulnStatus"`
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
func (c *NVDClient) ChangedSince(ctx context.Context, since time.Time) ([]app.ProposalFor, time.Time, error) {
	now := time.Now().UTC()
	if since.IsZero() {
		// Cold start: reach back a modest window rather than NVD's 120-day maximum. With the
		// relevance bound, a fresh deployment has few or no cards for those months anyway, so
		// the months would be fetched to match almost nothing.
		since = now.Add(-nvdColdStartWindow)
	}
	if since.Before(now.Add(-nvdMaxWindow)) {
		since = now.Add(-nvdMaxWindow) // NVD refuses a span wider than 120 days
	}
	// Bound THIS poll's span. Anything beyond is left for the next poll, which resumes from the
	// coverage instant returned below.
	end := now
	if end.Sub(since) > nvdMaxWalkPerPoll {
		end = since.Add(nvdMaxWalkPerPoll)
	}
	var out []app.ProposalFor
	width := nvdSliceWindow
	for cursor := since.UTC(); cursor.Before(end); {
		sliceEnd := cursor.Add(width)
		if sliceEnd.After(end) {
			sliceEnd = end
		}
		got, complete, err := c.fetchWindow(ctx, cursor, sliceEnd)
		if err != nil {
			// Report the coverage achieved BEFORE the failure, so a partial walk still makes
			// progress on the next poll instead of restarting from the same place forever.
			return out, cursor, err
		}
		if !complete {
			// The slice holds more than the page budget. Narrow it and retry the SAME
			// slice — the cursor does not advance, so nothing is skipped. The width is
			// left narrowed for the rest of this poll (a dense stretch tends to stay
			// dense) and resets on the next one.
			if width <= nvdMinSlice {
				return out, cursor, fmt.Errorf("%w: %s..%s holds more than %d records",
					ErrWindowTruncated, cursor.Format(nvdTimeLayout), sliceEnd.Format(nvdTimeLayout),
					nvdPageSize*nvdMaxPages)
			}
			width /= 2
			continue
		}
		out = append(out, got...)
		cursor = sliceEnd
	}
	return out, end, nil
}

// fetchWindow reads one modified-since slice, paginating up to nvdMaxPages. `complete`
// reports whether the slice was read in FULL; false means NVD holds more records for it than
// the budget allows. Returning that as a flag rather than swallowing it is the whole fix for
// NVD-WATCH-1 — the caller narrows the slice instead of dropping the remainder unnoticed.
func (c *NVDClient) fetchWindow(ctx context.Context, start, end time.Time) ([]app.ProposalFor, bool, error) {
	var out []app.ProposalFor
	startIndex := 0
	for page := 0; page < nvdMaxPages; page++ {
		resp, err := c.fetchPage(ctx, start, end, startIndex)
		if err != nil {
			return out, false, err
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
			return out, true, nil
		}
	}
	return out, false, nil
}

// VulnsForPackage discovers the CVEs affecting a component directly from NVD (A2 — the
// go-forward realization of D5 path 2 for NVD-only CVEs OSV never returns). NVD has no
// query-by-package, so it is triple-gated to honor D5's "never mirror the whole feed": (1) a
// bounded keyword-exact description search per component, capped at nvdMaxPages; (2) the
// CPE-product gate — only CVEs whose CPE config names a matching product survive; (3) the
// caller's reconciled version-range gate in correlation (A1) filters by version. It implements
// app.PackageVulnSource, so it slots beside OSV in the correlation discovery fan-out.
func (c *NVDClient) VulnsForPackage(ctx context.Context, comp app.InventoryComponent) ([]app.ProposalFor, error) {
	name := strings.TrimSpace(comp.Name)
	if name == "" {
		return nil, nil
	}
	var out []app.ProposalFor
	startIndex := 0
	for page := 0; page < nvdMaxPages; page++ {
		resp, err := c.fetchKeyword(ctx, name, startIndex)
		if err != nil {
			return out, err
		}
		for _, v := range resp.Vulnerabilities {
			if !nvdConfigsMatchProduct(v.CVE.Configurations, name) {
				continue // keyword hit but no matching CPE product — a mention, not an occurrence
			}
			pf, ok, terr := c.translate(v.CVE)
			if terr != nil || !ok {
				continue // no CVSS / unparseable — best-effort per record
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

// cpeProduct extracts the product from a CPE 2.3 URI
// (cpe:2.3:<part>:<vendor>:<product>:<version>:…) — field index 4, or "" if malformed.
func cpeProduct(criteria string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

// nvdConfigsMatchProduct reports whether any vulnerable CPE match names a product that
// normalized-equals name — the precision gate that turns a fuzzy keyword hit into a real
// "this CVE is about this component". Exact normalized equality (not substring) keeps false
// positives low: a missed match is safe (OSV + the watch still cover it), a wrong one is noise.
func nvdConfigsMatchProduct(configs []nvdConfig, name string) bool {
	want := normalizeProduct(name)
	if want == "" {
		return false
	}
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if m.Vulnerable && normalizeProduct(cpeProduct(m.Criteria)) == want {
					return true
				}
			}
		}
	}
	return false
}

// normalizeProduct lowercases and unifies "_"/"-" so a component name and a CPE product name
// compare on equal footing (CPE uses "_" where purls often use "-").
func normalizeProduct(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
}

func (c *NVDClient) fetchPage(ctx context.Context, start, end time.Time, startIndex int) (nvdLiveResponse, error) {
	q := url.Values{}
	q.Set("lastModStartDate", start.Format(nvdTimeLayout))
	q.Set("lastModEndDate", end.Format(nvdTimeLayout))
	q.Set("resultsPerPage", fmt.Sprintf("%d", nvdPageSize))
	q.Set("startIndex", fmt.Sprintf("%d", startIndex))
	return c.get(ctx, q, "nvd modified-since")
}

// fetchKeyword pulls one page of CVEs whose description exactly contains keyword — the
// bounded per-component discovery query (A2, EDR-KNOWLEDGE-01 D5). keywordExactMatch keeps the
// description search tight; the CPE-product gate (nvdConfigsMatchProduct) then confirms the CVE
// is actually about the component rather than merely mentioning its name.
func (c *NVDClient) fetchKeyword(ctx context.Context, keyword string, startIndex int) (nvdLiveResponse, error) {
	q := url.Values{}
	q.Set("keywordSearch", keyword)
	q.Set("keywordExactMatch", "")
	q.Set("resultsPerPage", fmt.Sprintf("%d", nvdPageSize))
	q.Set("startIndex", fmt.Sprintf("%d", startIndex))
	return c.get(ctx, q, "nvd keyword")
}

// get issues one NVD 2.0 CVE-API query and decodes the page.
func (c *NVDClient) get(ctx context.Context, q url.Values, label string) (nvdLiveResponse, error) {
	if err := c.pace(ctx); err != nil {
		return nvdLiveResponse{}, err
	}
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
		return nvdLiveResponse{}, fmt.Errorf("%s: %w", label, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nvdLiveResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return nvdLiveResponse{}, fmt.Errorf("%s: status %d: %s", label, resp.StatusCode, truncateForError(data))
	}
	var parsed nvdLiveResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nvdLiveResponse{}, fmt.Errorf("%s: decode: %w", label, err)
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
var (
	_ app.CVEVulnSource     = (*NVDClient)(nil)
	_ app.PackageVulnSource = (*NVDClient)(nil)
)

// VulnsForCVE fetches ONE CVE by id — the per-subject enrichment path (EDR-KNOWLEDGE-01 D5a),
// and the shape every other feed in this context already uses.
//
// This replaces the modified-since window walk for enrichment. The walk asked NVD what changed
// everywhere and then discarded almost all of it: measured 2026-08-07, 3,207 records fetched to
// apply 18, at ~84 seconds per day of window. Asking by id makes the relevance bound structural
// rather than a post-fetch filter — nothing is retrieved that could be discarded — and it also
// covers MORE, because a CVE whose last modification predates the window was unreachable by the
// walk at any page budget.
//
// found=false when NVD has no record, or has one it has never scored: a Proposal carrying no
// severity would add a source to the card without adding a fact, and the reconciled headline
// would gain a contender with nothing to contend.
func (c *NVDClient) VulnsForCVE(ctx context.Context, cve value.CVEID) (app.CVEFacts, error) {
	q := url.Values{}
	q.Set("cveId", cve.String())
	resp, err := c.get(ctx, q, "nvd by-cve")
	if err != nil {
		return app.CVEFacts{}, err
	}
	for _, v := range resp.Vulnerabilities {
		// Withdrawal first: a rejected record may still carry old metrics, and enriching from
		// them would refresh a card that should be retired.
		if nvdRejected(v.CVE.VulnStatus) {
			return app.CVEFacts{Withdrawn: true}, nil
		}
		pf, ok, terr := c.translate(v.CVE)
		if terr != nil || !ok {
			continue
		}
		return app.CVEFacts{Proposal: pf, Found: true}, nil
	}
	return app.CVEFacts{}, nil
}

// nvdRejected reports whether NVD's vulnStatus means the CVE was withdrawn.
//
// Matched case-insensitively on a contained token rather than by equality: NVD has used both
// "Rejected" and "Rejected by CNA", and a status this consequential must not be missed over
// wording. Erring toward detection is the safe direction — the consequence is that a card is
// superseded, which is a governed, reversible-by-reopening event, not a deletion.
func nvdRejected(status string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(status)), "rejected")
}
