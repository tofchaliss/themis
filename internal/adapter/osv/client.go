package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// /v1/query returns full vulnerability records (aliases, severity, affected
// ranges) for a package. The previous /v1/querybatch endpoint returns only vuln
// IDs, which left findings keyed by the OSV id (GHSA-…) with no severity and no
// version range — so they could never resolve to a canonical CVE or be enriched.
const defaultBaseURL = "https://api.osv.dev/v1/query"

// ClientConfig configures the OSV HTTP client.
type ClientConfig struct {
	BaseURL     string
	HTTPClient  *http.Client
	RateLimiter *TokenBucket
}

// Client queries the OSV batch API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	limiter    *TokenBucket
}

// NewClient creates an OSV feed client with token-bucket rate limiting.
func NewClient(cfg ClientConfig) *Client {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	limiter := cfg.RateLimiter
	if limiter == nil {
		limiter = NewTokenBucket(10, 10)
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		limiter:    limiter,
	}
}

// QueryByEcosystem queries OSV for each package in an ecosystem via /v1/query,
// which returns full records (so the canonical CVE alias, severity, and version
// ranges are available). /v1/query is single-package, so a multi-package call
// (the watch fallback) issues one rate-limited request per package; the common
// ingest path queries one package at a time already.
func (c *Client) QueryByEcosystem(ctx context.Context, ecosystem string, packages []domain.OSVPackageQuery) ([]domain.FeedVulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	osvEco, ok := MapEcosystem(ecosystem)
	if !ok {
		return nil, nil
	}
	var out []domain.FeedVulnerability
	for _, pkg := range packages {
		vulns, err := c.queryPackage(ctx, ecosystem, osvEco, pkg.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, vulns...)
	}
	return out, nil
}

// queryPackage issues one /v1/query for a single package. It queries by the
// normalized name but tags results with the caller's original name so the
// downstream identity match is unchanged.
func (c *Client) queryPackage(ctx context.Context, ecosystem, osvEco, name string) ([]domain.FeedVulnerability, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	reqBody := queryRequest{Package: packageRef{Ecosystem: osvEco, Name: normalizePackageName(ecosystem, name)}}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("osv api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload queryResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	out := make([]domain.FeedVulnerability, 0, len(payload.Vulns))
	for _, vuln := range payload.Vulns {
		out = append(out, mapOSVVuln(vuln, ecosystem, name))
	}
	return out, nil
}

type queryRequest struct {
	Package packageRef `json:"package"`
}

type packageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type queryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Related  []string `json:"related"`
	Upstream []string `json:"upstream"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

// osvAffected is one OSV `affected` entry: the package plus its version ranges and
// explicit version list.
type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

// osvPackage identifies the affected package (ecosystem + name).
type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvRange is one version range: its type (SEMVER / ECOSYSTEM / GIT) and its
// ordered introduced/fixed/last_affected events.
type osvRange struct {
	Type   string          `json:"type"`
	Events []osvRangeEvent `json:"events"`
}

type osvRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

func mapOSVVuln(vuln osvVuln, ecosystem, packageName string) domain.FeedVulnerability {
	score, vector := extractCVSSFromSeverity(vuln.Severity)
	severity := severityFromScore(score)

	osvEcosystem, _ := MapEcosystem(ecosystem)
	affected := extractAffectedVersions(vuln, osvEcosystem, packageName)
	fixes := extractFixVersions(vuln, osvEcosystem, packageName)

	return domain.FeedVulnerability{
		CVEID:            resolveCVEID(vuln),
		Severity:         severity,
		CVSSScore:        score,
		CVSSVector:       vector,
		Ecosystem:        ecosystem,
		PackageName:      packageName,
		AffectedVersions: affected,
		FixVersions:      fixes,
		Source:           domain.FindingSourceOSV,
	}
}

// resolveCVEID prefers a canonical CVE from aliases, then upstream/related
// (distros vary on where they record it), falling back to the OSV id only when
// no CVE is referenced anywhere.
func resolveCVEID(vuln osvVuln) string {
	for _, group := range [][]string{vuln.Aliases, vuln.Upstream, vuln.Related} {
		for _, id := range group {
			normalized := domain.NormalizeCVEID(id)
			if strings.HasPrefix(strings.ToUpper(normalized), "CVE-") {
				return normalized
			}
		}
	}
	return domain.NormalizeCVEID(vuln.ID)
}

// extractAffectedVersions turns the OSV `affected` block into constraint groups
// for domain.VersionMatches. It only reads entries for the queried package
// (advisories often list several packages/distros), pairs each range's ordered
// introduced/fixed/last_affected events into a single AND group (e.g.
// ">= 1.0.0, < 2.0.0"), and refuses to fall back to a match-all "unknown" when a
// range is present but unparseable — that fail-open default was a primary cause
// of inflated finding counts on apk SBOMs.
func extractAffectedVersions(vuln osvVuln, osvEcosystem, packageName string) []string {
	var groups []string
	matchedPackage := false
	for _, item := range vuln.Affected {
		if !affectedItemMatches(item.Package.Ecosystem, item.Package.Name, osvEcosystem, packageName) {
			continue
		}
		matchedPackage = true
		for _, v := range item.Versions {
			if v = strings.TrimSpace(v); v != "" {
				groups = append(groups, v)
			}
		}
		for _, rng := range item.Ranges {
			if isUnusableRangeType(rng.Type) {
				continue
			}
			if g := rangeConstraintGroup(rng.Events); g != "" {
				groups = append(groups, g)
			}
		}
		// An affected entry with neither ranges nor explicit versions means the
		// whole package is affected (OSV semantics) — keep that as match-all.
		if len(item.Versions) == 0 && len(item.Ranges) == 0 {
			groups = append(groups, "*")
		}
	}
	switch {
	case !matchedPackage:
		// OSV returned this advisory for the queried package but no affected
		// entry aligned to it (e.g. the name is spelled differently). Preserve
		// recall — a false positive is safer than hiding a real finding.
		return []string{"*"}
	case len(groups) == 0:
		// Matched the package but every range was unusable. Do not claim all
		// versions are affected.
		return []string{"none"}
	default:
		return groups
	}
}

// rangeConstraintGroup pairs an OSV range's ordered events into one AND group.
// An `introduced` opens the range; a `fixed`/`last_affected` closes it. A range
// left open (introduced with no fix) affects everything from the introduced
// version onward.
func rangeConstraintGroup(events []osvRangeEvent) string {
	var bounds []string
	introduced := ""
	open := false
	closeRange := func(upper string) {
		if introduced != "" && introduced != "0" {
			bounds = append(bounds, ">= "+introduced)
		}
		bounds = append(bounds, upper)
		introduced = ""
		open = false
	}
	for _, e := range events {
		switch {
		case e.Introduced != "":
			introduced = strings.TrimSpace(e.Introduced)
			open = true
		case e.Fixed != "":
			closeRange("< " + strings.TrimSpace(e.Fixed))
		case e.LastAffected != "":
			closeRange("<= " + strings.TrimSpace(e.LastAffected))
		}
	}
	if open {
		if introduced != "" && introduced != "0" {
			bounds = append(bounds, ">= "+introduced)
		} else {
			bounds = append(bounds, "*") // introduced "0", no fix → all versions
		}
	}
	return strings.Join(bounds, ", ")
}

// affectedItemMatches reports whether an OSV affected entry belongs to the
// queried package. Name match is required; ecosystem must match when both sides
// declare one (advisories may omit it).
func affectedItemMatches(itemEcosystem, itemName, osvEcosystem, packageName string) bool {
	if !strings.EqualFold(strings.TrimSpace(itemName), strings.TrimSpace(packageName)) {
		return false
	}
	if itemEcosystem != "" && osvEcosystem != "" &&
		!strings.EqualFold(strings.TrimSpace(itemEcosystem), strings.TrimSpace(osvEcosystem)) {
		return false
	}
	return true
}

func extractFixVersions(vuln osvVuln, osvEcosystem, packageName string) []string {
	var fixes []string
	for _, item := range vuln.Affected {
		if !affectedItemMatches(item.Package.Ecosystem, item.Package.Name, osvEcosystem, packageName) {
			continue
		}
		for _, rng := range item.Ranges {
			if isUnusableRangeType(rng.Type) {
				continue
			}
			for _, event := range rng.Events {
				if event.Fixed != "" && event.Fixed != "0" {
					fixes = append(fixes, strings.TrimSpace(event.Fixed))
				}
			}
		}
	}
	return fixes
}

// isUnusableRangeType reports whether an OSV range type carries no usable version
// bound. GIT ranges express introduced/fixed as commit hashes, not versions —
// feeding them to rangeConstraintGroup produces a bogus constraint (a low semver
// like "3.1.6" sorts below a hex commit id, so it matches "< 9b53045c…") and leaks
// the commit hash as a "fixed" version. OSV always attaches a SEMVER/ECOSYSTEM
// range (or an explicit versions list) when an ecosystem fix exists — e.g. the
// Jinja2 CVE-2016-10745 record carries both a GIT range and "ECOSYSTEM < 2.8.1" —
// so skipping GIT ranges is safe; an entry left with no usable range fails closed
// via the existing "none" sentinel rather than over-matching on commit hashes.
func isUnusableRangeType(rangeType string) bool {
	return strings.EqualFold(strings.TrimSpace(rangeType), "GIT")
}
