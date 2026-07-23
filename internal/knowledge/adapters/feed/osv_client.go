package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// OSVBaseURL is the default OSV.dev API endpoint.
const OSVBaseURL = "https://api.osv.dev"

// OSVClient is the real OSV **query-by-package** feed-fetch client (EDR-KNOWLEDGE-01 D5):
// given a release component it POSTs OSV's /v1/query and hands each returned OSV record
// to the OSV ACL, yielding vuln-facts Proposals bound to a canonical CVE. It implements
// app.PackageVulnSource — the lazy-discovery seam M7 left as a fakeable port. Discovery
// stays bounded by the components the enterprise has actually seen.
type OSVClient struct {
	baseURL string
	http    *http.Client
	acl     osvACL
}

// NewOSVClient builds a client against the OSV base URL (default OSVBaseURL). A nil
// http.Client falls back to http.DefaultClient.
func NewOSVClient(baseURL string, hc *http.Client) *OSVClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = OSVBaseURL
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &OSVClient{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryRequest struct {
	Version string          `json:"version,omitempty"`
	Package osvQueryPackage `json:"package"`
}

// osvQueryResponse holds OSV records verbatim — each element is a full OSV record the
// osvACL already knows how to translate, so no external shape leaks past the ACL.
type osvQueryResponse struct {
	Vulns []json.RawMessage `json:"vulns"`
}

// VulnsForPackage queries OSV for the component's package and translates every returned
// record into a Proposal. A component OSV cannot address (no mappable ecosystem/name) is
// a no-op — those are covered by the distro feeds / NVD watch. Records OSV returns that
// carry no canonical CVE (GHSA-only) are skipped: Knowledge is CVE-keyed and discovery
// is best-effort per record, never all-or-nothing.
func (c *OSVClient) VulnsForPackage(ctx context.Context, comp app.InventoryComponent) ([]app.ProposalFor, error) {
	eco := osvEcosystem(comp)
	name := osvPackageName(comp)
	if eco == "" || name == "" {
		return nil, nil
	}

	body, err := json.Marshal(osvQueryRequest{
		Version: strings.TrimSpace(comp.Version),
		Package: osvQueryPackage{Name: name, Ecosystem: eco},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query %s/%s: %w", eco, name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv query %s/%s: status %d: %s", eco, name, resp.StatusCode, truncateForError(data))
	}

	var qr osvQueryResponse
	if err := json.Unmarshal(data, &qr); err != nil {
		return nil, fmt.Errorf("osv query %s/%s: decode: %w", eco, name, err)
	}

	var out []app.ProposalFor
	for _, rec := range qr.Vulns {
		translated, terr := c.acl.Translate(rec)
		if terr != nil {
			// No canonical CVE (GHSA-only) or an unparseable record — skip and continue.
			continue
		}
		for _, t := range translated {
			out = append(out, app.ProposalFor{CVE: t.CVE, Proposal: t.Proposal})
		}
	}
	return out, nil
}

// osvEcosystem maps a component to its OSV ecosystem name, preferring the PURL type
// (authoritative) and falling back to a supplied OSV-style ecosystem label. Distro
// packages (apk/deb/rpm) return "" — they are correlated by the distro OSV feeds, not
// query-by-package.
func osvEcosystem(comp app.InventoryComponent) string {
	switch purlType(comp.PURL) {
	case "pypi":
		return "PyPI"
	case "maven":
		return "Maven"
	case "npm":
		return "npm"
	case "golang":
		return "Go"
	case "gem":
		return "RubyGems"
	case "cargo":
		return "crates.io"
	case "nuget":
		return "NuGet"
	case "composer":
		return "Packagist"
	case "hex":
		return "Hex"
	case "pub":
		return "Pub"
	case "apk", "deb", "rpm":
		return "" // distro — handled by the distro OSV feeds
	}
	// Fall back to an already-OSV-shaped ecosystem label if the PURL type was unknown.
	switch strings.ToLower(strings.TrimSpace(comp.Ecosystem)) {
	case "pypi":
		return "PyPI"
	case "maven":
		return "Maven"
	case "npm":
		return "npm"
	case "go", "golang":
		return "Go"
	default:
		return ""
	}
}

// osvPackageName derives the OSV package name from the PURL: Maven wants
// "group:artifact", npm keeps its "@scope/name", others use the bare name. Falls back to
// the component's Name.
func osvPackageName(comp app.InventoryComponent) string {
	ns, name := purlNamespaceName(comp.PURL)
	if name == "" {
		return strings.TrimSpace(comp.Name)
	}
	switch purlType(comp.PURL) {
	case "maven":
		if ns != "" {
			return ns + ":" + name
		}
	case "npm", "composer", "golang":
		if ns != "" {
			return ns + "/" + name
		}
	}
	return name
}

// purlType returns the PURL type (the token between "pkg:" and the first "/").
func purlType(purl string) string {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := purl[len("pkg:"):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return strings.ToLower(rest[:i])
	}
	return ""
}

// purlNamespaceName splits a PURL's namespace and name (version/qualifiers stripped).
func purlNamespaceName(purl string) (namespace, name string) {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return "", ""
	}
	rest := purl[len("pkg:"):]
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "", ""
	}
	rest = rest[i+1:] // drop the type
	// Strip subpath (#...) and qualifiers (?...) first, then the version at the LAST
	// '@' — npm scoped names begin with '@', so a first-match strip would be wrong.
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.IndexByte(rest, '?'); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.LastIndexByte(rest, '@'); j >= 0 {
		rest = rest[:j]
	}
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return "", ""
	}
	if j := strings.LastIndexByte(rest, '/'); j >= 0 {
		return rest[:j], rest[j+1:]
	}
	return "", rest
}

// truncateForError bounds error bodies so a huge feed response cannot flood a log line.
func truncateForError(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// ensure the port is satisfied at compile time.
var _ app.PackageVulnSource = (*OSVClient)(nil)
