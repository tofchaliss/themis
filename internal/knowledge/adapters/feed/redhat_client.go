package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// defaultRedHatBaseURL is Red Hat's public Security Data API (Hydra). It serves a per-CVE
// document at /cve/<CVE>.json — the relevance-bounded fetch a card population drives (D5). No
// API key: the endpoint is public and unauthenticated.
const defaultRedHatBaseURL = "https://access.redhat.com/hydra/rest/securitydata"

// redhatFixStateNotAffected is the Red Hat package_state fix_state that maps to a VEX
// not_affected applicability statement (the vendor's backport/scope signal).
const redhatFixStateNotAffected = "not affected"

// RedHatClient fetches a CVE's Red Hat Security Data document and translates it into source
// Proposals: the vendor-severity vuln-facts Proposal (when a CVSS is present) plus one
// not_affected applicability Proposal per package Red Hat marks "Not affected". It implements
// app.RedHatCVESource. Silent on a not-found CVE (Red Hat tracks no such id) — that is a normal
// gap, returned as no Proposals rather than an error.
type RedHatClient struct {
	baseURL string
	http    *http.Client
}

// NewRedHatClient builds the client over the given base URL ("" → the public Hydra default) and
// HTTP client (nil → http.DefaultClient).
func NewRedHatClient(baseURL string, httpClient *http.Client) *RedHatClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultRedHatBaseURL
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &RedHatClient{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

var _ app.RedHatCVESource = (*RedHatClient)(nil)

// redhatCVEDocument is the subset of Red Hat's Security Data CVE document the ACL consumes.
// Note cvss3.cvss3_base_score is a STRING in the Hydra JSON.
type redhatCVEDocument struct {
	Name           string `json:"name"`
	ThreatSeverity string `json:"threat_severity"`
	PublicDate     string `json:"public_date"`
	CVSS3          struct {
		BaseScore string `json:"cvss3_base_score"`
		Vector    string `json:"cvss3_scoring_vector"`
	} `json:"cvss3"`
	PackageState []struct {
		ProductName string `json:"product_name"`
		FixState    string `json:"fix_state"`
		PackageName string `json:"package_name"`
	} `json:"package_state"`
	AffectedRelease []struct {
		Package string `json:"package"` // the fixed build's NEVRA (name-[epoch:]version-release[.arch])
		CPE     string `json:"cpe"`     // the advisory product CPE — carries the EL stream
	} `json:"affected_release"`
}

// FetchCVE fetches and translates one CVE's Red Hat document. A 404 (Red Hat tracks no such
// CVE) returns no Proposals and no error; any other non-200 is a real error.
func (c *RedHatClient) FetchCVE(ctx context.Context, cve string) ([]app.ProposalFor, error) {
	cveID, err := value.NewCVEID(cve)
	if err != nil {
		return nil, nil // a carded id that no longer parses — skip defensively (not our error)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/cve/"+cveID.String()+".json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Red Hat has no record for this CVE — a normal gap, not an error
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("redhat: GET cve/%s: status %d", cveID.String(), resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var doc redhatCVEDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("redhat: invalid json for %s: %w", cveID.String(), err)
	}
	observedAt, ok := parseRedHatDate(doc.PublicDate)
	if !ok {
		return nil, nil // no reconcilable observation time — skip this record defensively
	}

	var out []app.ProposalFor

	// Main-stream fixed builds (EDR-VEX-01 Phase 3): the vendor fix NEVRA per EL stream, keeping
	// only MAIN-stream advisories (excluding EUS/AUS/E4S/TUS via the CPE) so correlation's
	// stream-scoped fixed verdict never compares a rolling install against a minor-locked backport.
	var fixes []string
	for _, ar := range doc.AffectedRelease {
		pkg := strings.TrimSpace(ar.Package)
		if pkg == "" || !redhatIsMainStream(ar.CPE) {
			continue
		}
		fixes = append(fixes, pkg)
	}

	// Vendor-severity vuln-facts (only when a CVSS is present — mirror the NVD ACL's drop-no-CVSS
	// so a Red Hat CVE without CVSS3 never pollutes the reconciled headline with a zero score). The
	// main-stream fixed builds ride here so they reach the reconciled view's FixedVersions.
	if cvss, cok := parseRedHatCVSS(doc.CVSS3.BaseScore, doc.CVSS3.Vector); cok {
		facts := domain.VulnFacts{
			Severity:      severityFrom(redhatSeverityLabel(doc.ThreatSeverity), cvss),
			CVSS:          cvss,
			FixedVersions: fixes,
		}
		if p, perr := domain.NewVulnFactsProposal("redhat", observedAt, facts); perr == nil {
			out = append(out, app.ProposalFor{CVE: cveID, Proposal: p})
		}
	}

	// not_affected applicability, one per distinct package Red Hat marks "Not affected". The
	// per-EL-stream verdict precision (rhel-8 vs rhel-9) is PR3; here the statement keys on the
	// package name, which Governance matches to a Finding's component (Phase-2 overlay).
	seen := map[string]struct{}{}
	for _, ps := range doc.PackageState {
		if !strings.EqualFold(strings.TrimSpace(ps.FixState), redhatFixStateNotAffected) {
			continue
		}
		pkg := strings.TrimSpace(ps.PackageName)
		if pkg == "" {
			continue
		}
		if _, dup := seen[pkg]; dup {
			continue
		}
		seen[pkg] = struct{}{}
		app0 := domain.Applicability{
			Package:       pkg,
			Status:        "not_affected",
			Justification: "Red Hat: not affected" + productSuffix(ps.ProductName),
		}
		if p, perr := domain.NewApplicabilityProposal("redhat", observedAt, app0); perr == nil {
			out = append(out, app.ProposalFor{CVE: cveID, Proposal: p})
		}
	}
	return out, nil
}

// redhatSeverityLabel maps Red Hat's threat_severity vocabulary to the canonical severity
// labels ParseSeverity understands (moderate→medium, important→high); an unrecognized value
// yields "" so severityFrom falls back to the CVSS band.
func redhatSeverityLabel(threat string) string {
	switch strings.ToLower(strings.TrimSpace(threat)) {
	case "low":
		return "low"
	case "moderate":
		return "medium"
	case "important":
		return "high"
	case "critical":
		return "critical"
	default:
		return ""
	}
}

// parseRedHatCVSS parses Hydra's string base score + vector into a CVSS. Reports false when the
// score is absent or unparseable (no CVSS to fold).
func parseRedHatCVSS(baseScore, vector string) (value.CVSS, bool) {
	s := strings.TrimSpace(baseScore)
	if s == "" {
		return value.CVSS{}, false
	}
	score, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return value.CVSS{}, false
	}
	cvss, err := value.NewCVSS(score, vector)
	if err != nil {
		return value.CVSS{}, false
	}
	return cvss, true
}

// parseRedHatDate parses Red Hat's public_date (RFC 3339, or a bare YYYY-MM-DD). Reports false
// when neither form parses.
func parseRedHatDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// productSuffix renders the vendor product/stream into the justification when present.
func productSuffix(product string) string {
	product = strings.TrimSpace(product)
	if product == "" {
		return ""
	}
	return " in " + product
}

// redhatIsMainStream reports whether an advisory CPE is a MAIN-stream RHEL product — an
// `enterprise_linux` CPE that is NOT a minor-locked backport line (EUS / AUS / E4S / TUS).
// Only main-stream fixes are surfaced for the stream-scoped fixed verdict (EDR-VEX-01 Phase 3):
// a rolling main-stream install compared against a minor-locked backport fix can produce a false
// "fixed" (the backport's lower release number outranks nothing), so those lines are excluded.
func redhatIsMainStream(cpe string) bool {
	c := strings.ToLower(cpe)
	if !strings.Contains(c, "enterprise_linux") {
		return false
	}
	for _, backport := range []string{"eus", "aus", "e4s", "tus"} {
		if strings.Contains(c, backport) {
			return false
		}
	}
	return true
}
