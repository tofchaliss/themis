package report

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// nessusVersion is this converter's identity in provenance (`converted_by`).
const nessusVersion = "nessus@2"

// nessusRoot is the root element a `.nessus` export carries (EDR-INTAKE-01, 2026-10-24
// amendment N1). The v1 schema (`NessusClientData`) is not admitted: it is long retired and
// nobody has asked for it.
const nessusRoot = "NessusClientData_v2"

// nessusLocalChecks is the plugin-family suffix of a vendor advisory check — `Red Hat Local
// Security Checks`, `Rocky Linux Local Security Checks` and so on. Together with the package
// lines it is what makes a result class A (N3).
const nessusLocalChecks = "Local Security Checks"

// nessusInstalled and nessusShouldBe read the two package lines of a vendor advisory check.
// Anchored on whole lines: the plugin output is free text, and a looser pattern is how a
// sentence that happens to contain a colon becomes a package.
var (
	nessusInstalled = regexp.MustCompile(`^\s*Remote package installed\s*:\s*(\S+)\s*$`)
	nessusShouldBe  = regexp.MustCompile(`^\s*Should be\s*:\s*(\S+)\s*$`)
)

type nessusDoc struct {
	Reports []struct {
		Hosts []nessusHost `xml:"ReportHost"`
	} `xml:"Report"`
}

type nessusHost struct {
	Props []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:",chardata"`
	} `xml:"HostProperties>tag"`
	Items []nessusItem `xml:"ReportItem"`
}

type nessusItem struct {
	PluginID     string   `xml:"pluginID,attr"`
	PluginName   string   `xml:"pluginName,attr"`
	PluginFamily string   `xml:"pluginFamily,attr"`
	CVEs         []string `xml:"cve"`
	CPEs         []string `xml:"cpe"`
	RiskFactor   string   `xml:"risk_factor"`
	CVSS3Score   string   `xml:"cvss3_base_score"`
	CVSS3Vector  string   `xml:"cvss3_vector"`
	Output       string   `xml:"plugin_output"`
}

// nessusPackage is one `Remote package installed` line and the `Should be` line after it.
type nessusPackage struct {
	name, version, fixed string
}

// nessusXML converts a Tenable Nessus `.nessus` export into the curated document
// (EDR-INTAKE-01, 2026-10-24 amendment N1–N10).
//
// Only a vendor advisory check (class A: a `… Local Security Checks` plugin with
// `Remote package installed` lines) becomes a finding, one per CVE × package line. Every
// other result carrying a CVE — mostly upstream version checks, which on a distribution that
// backports fixes are mostly false — is counted as skipped, never filed (N3). A result with
// no CVE is not a vulnerability record and is not counted at all.
//
// Three rules carry the identity judgement:
//
//   - no purl is ever built (N4): the package line gives name + version + `rpm`, and the
//     finding resolves onto its SBOM twin by the existing purl-less path, or is reported
//     unresolved;
//   - nothing about the host reaches the output (N8) — no address, name or plugin text;
//   - every host in the file is filed under the one release the request names (N2), and
//     identical findings from several hosts are kept, not merged, so the counts stay a pair
//     whose difference is exactly what was filed.
type nessusXML struct{}

func (nessusXML) Version() string { return nessusVersion }

func (nessusXML) Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	if !utf8.Valid(body) {
		return nil, Stats{}, fmt.Errorf("%w: the XML body is not valid UTF-8", ErrMalformedBody)
	}
	root, isXML, err := xmlRoot(body)
	if err != nil {
		return nil, Stats{}, err
	}
	if !isXML || root != nessusRoot {
		return nil, Stats{}, fmt.Errorf("%w: a Nessus report is an XML document whose root is <%s>", ErrMalformedBody, nessusRoot)
	}
	var doc nessusDoc
	if err := newXMLDecoder(body).Decode(&doc); err != nil {
		return nil, Stats{}, fmt.Errorf("%w: the Nessus report does not parse: %v", ErrMalformedBody, err)
	}

	var hosts []nessusHost
	for _, r := range doc.Reports {
		hosts = append(hosts, r.Hosts...)
	}
	hostTimes := make([]time.Time, len(hosts))
	var derived time.Time
	for i, h := range hosts {
		hostTimes[i] = nessusHostTime(h)
		if hostTimes[i].After(derived) {
			derived = hostTimes[i]
		}
	}
	resolved, err := resolveObservedAt(observedAt, derived, "no host carries a parseable HOST_END_TIMESTAMP, HOST_START_TIMESTAMP or HOST_END")
	if err != nil {
		return nil, Stats{}, err
	}

	var (
		stats    Stats
		findings []curatedFinding
	)
	for i, h := range hosts {
		// A supplied timestamp is an assertion about the whole observation (D3); without
		// one each host keeps its own, and a host with none takes the document's.
		at := resolved
		if observedAt.IsZero() && !hostTimes[i].IsZero() {
			at = hostTimes[i]
		}
		observed := at.Format("2006-01-02T15:04:05.000Z")
		installs := nessusHostInstalls(h)
		for _, it := range h.Items {
			cves := nessusCVEs(it.CVEs)
			if len(cves) == 0 {
				continue
			}
			pkgs, bad := nessusPackages(it.Output)
			if !strings.HasSuffix(strings.TrimSpace(it.PluginFamily), nessusLocalChecks) || (len(pkgs) == 0 && bad == 0) {
				// Class B/C, or a local check with no package line. A class C block — the
				// path of a hand-installed component this host's detection plugins
				// established (H1) — is filed (H3); every other such result is counted,
				// never filed.
				sc, vector := nessusScore(it)
				kept, total := nessusClassC(it.Output, installs, cves, func(cve string, inst nessusInstall, fixed []string) {
					findings = append(findings, curatedFinding{
						CVE: cve, ObservedAt: observed, Scanner: "nessus",
						Severity: nessusSeverity(it.RiskFactor), Score: sc, CVSSVector: vector,
						Fixed:     fixed,
						Component: curatedComponent{Name: inst.product, Version: inst.version},
					})
				})
				stats.FindingsTotal += total
				stats.FindingsSkipped += total - kept
				continue
			}
			stats.FindingsTotal += len(cves) * (len(pkgs) + bad)
			stats.FindingsSkipped += len(cves) * bad
			sc, vector := nessusScore(it)
			for _, cve := range cves {
				for _, p := range pkgs {
					var fixed []string
					if p.fixed != "" {
						fixed = []string{p.fixed}
					}
					findings = append(findings, curatedFinding{
						CVE:        cve,
						ObservedAt: observed,
						Scanner:    "nessus",
						Severity:   nessusSeverity(it.RiskFactor),
						Score:      sc,
						CVSSVector: vector,
						Fixed:      fixed,
						Component: curatedComponent{
							Name:      p.name,
							Version:   p.version,
							Ecosystem: "rpm",
						},
					})
				}
			}
		}
	}
	return encodeDocument(findings, encodingJS), stats, nil
}

// nessusHostInstalls applies the hand-install rule (H1) to one host of the export: its
// detection plugins, read against its package list.
func nessusHostInstalls(h nessusHost) nessusInstallIndex {
	var (
		items []nessusDetection
		rpms  map[string]struct{}
	)
	for _, it := range h.Items {
		if it.PluginID == nessusSoftwarePlugin {
			rpms = nessusRPMNames(it.Output)
		}
		items = append(items, nessusDetection{
			pluginID: it.PluginID, pluginName: it.PluginName, output: it.Output, cves: it.CVEs, cpes: it.CPEs,
		})
	}
	return nessusInstalls(items, rpms)
}

// nessusClassC files the blocks of an upstream version check that name a hand-installed
// component (H3) and counts the rest. A result with no path block (a banner check) is one
// skipped record per CVE, as before; a result with blocks is one record per CVE per block, so
// the pair of counts says exactly how many paths were judged and how many were filed.
func nessusClassC(output string, installs nessusInstallIndex, cves []string, file func(cve string, inst nessusInstall, fixed []string)) (kept, total int) {
	blocks := nessusVulnBlocks(output)
	if len(blocks) == 0 {
		return 0, len(cves)
	}
	for _, b := range blocks {
		inst, ok := installs[b.path]
		if !ok {
			continue
		}
		var fixed []string
		if b.fixed != "" {
			fixed = []string{b.fixed}
		}
		if b.version != "" {
			inst.version = b.version // the version Nessus compared, which is what the fix is relative to
		}
		for _, cve := range cves {
			file(cve, inst, fixed)
		}
		kept += len(cves)
	}
	return kept, len(cves) * len(blocks)
}

// nessusCVEs keeps the non-empty CVE elements, trimmed, in document order.
func nessusCVEs(raw []string) []string {
	var out []string
	for _, c := range raw {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// nessusPackages reads the `Remote package installed` / `Should be` pairs of a vendor
// advisory check. A `Should be` line belongs to the installed line before it. `bad` counts
// installed lines whose package name could not be split (N4) — each is a skip, not a guess.
func nessusPackages(output string) (pkgs []nessusPackage, bad int) {
	current := -1
	for _, line := range strings.Split(output, "\n") {
		if m := nessusInstalled.FindStringSubmatch(line); m != nil {
			name, version, ok := splitNVR(m[1])
			if !ok {
				bad++
				current = -1
				continue
			}
			pkgs = append(pkgs, nessusPackage{name: name, version: version})
			current = len(pkgs) - 1
			continue
		}
		if m := nessusShouldBe.FindStringSubmatch(line); m != nil && current >= 0 {
			if _, fixed, ok := splitNVR(m[1]); ok {
				pkgs[current].fixed = fixed
			}
			current = -1
		}
	}
	return pkgs, bad
}

// splitNVR splits an RPM `name-version-release` by the RPM rule: the last two hyphens
// separate version and release, everything before them is the name. The returned version
// is `version-release`, with an `E:` epoch kept as written (N4) — it is compared with the
// SBOM inventory's version as is.
func splitNVR(nvr string) (name, version string, ok bool) {
	rel := strings.LastIndexByte(nvr, '-')
	if rel <= 0 || rel == len(nvr)-1 {
		return "", "", false
	}
	ver := strings.LastIndexByte(nvr[:rel], '-')
	if ver <= 0 || ver == rel-1 {
		return "", "", false
	}
	return nvr[:ver], nvr[ver+1:], true
}

// nessusScore takes the CVSS 3 base score and vector. An absent or unparseable score is
// the integer zero, as every other converter writes it.
func nessusScore(it nessusItem) (score, string) {
	return nessusCSVScore(strings.TrimSpace(it.CVSS3Score)), strings.TrimSpace(it.CVSS3Vector)
}

// nessusSeverity passes Nessus's risk factor through, except `None`, which would otherwise
// parse as a real band and override the CVSS score (N7).
func nessusSeverity(risk string) string {
	if strings.EqualFold(strings.TrimSpace(risk), "none") {
		return ""
	}
	return strings.TrimSpace(risk)
}

// nessusHostTime is the host's own scan time (N6): the end timestamp, else the start
// timestamp, both unix seconds, else `HOST_END` in Nessus's ANSI-C layout, read as UTC
// because the export names no zone. Zero when none parses.
func nessusHostTime(h nessusHost) time.Time {
	props := map[string]string{}
	for _, p := range h.Props {
		props[p.Name] = strings.TrimSpace(p.Value)
	}
	for _, k := range []string{"HOST_END_TIMESTAMP", "HOST_START_TIMESTAMP"} {
		if s, err := strconv.ParseInt(props[k], 10, 64); err == nil && s > 0 {
			return time.Unix(s, 0).UTC()
		}
	}
	if t, err := time.Parse(time.ANSIC, props["HOST_END"]); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// xmlLooksLikeXML reports whether the body opens with `<` after a BOM and whitespace — the
// one cheap test that sends a body down the XML road (D5a row 1b) without reading it.
func xmlLooksLikeXML(body []byte) bool {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(body, utf8BOM), " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '<'
}

// xmlRoot reads tokens up to the first element and returns its local name. isXML is false
// for a body that does not open as XML at all. A DTD declaring an entity is refused rather
// than skipped: the decoder would not expand it, but a document that depends on an entity
// nobody expands is a document we cannot read honestly.
func xmlRoot(body []byte) (root string, isXML bool, err error) {
	if !xmlLooksLikeXML(body) {
		return "", false, nil
	}
	d := newXMLDecoder(body)
	for {
		tok, terr := d.Token()
		if terr != nil {
			if errors.Is(terr, io.EOF) {
				return "", true, fmt.Errorf("%w: the XML body has no root element", ErrMalformedBody)
			}
			return "", true, fmt.Errorf("%w: the body opens as XML but does not parse: %v", ErrMalformedBody, terr)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t.Name.Local, true, nil
		case xml.Directive:
			if bytes.Contains(t, []byte("ENTITY")) {
				return "", true, fmt.Errorf("%w: the XML body declares an entity, which Themis does not expand", ErrMalformedBody)
			}
		}
	}
}

// newXMLDecoder reads past a UTF-8 BOM (for parsing only; the submitted bytes are what is
// fingerprinted) in strict mode, with no entity map and no charset reader, so a document
// that names another encoding or an undeclared entity fails instead of being guessed at.
func newXMLDecoder(body []byte) *xml.Decoder {
	d := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(body, utf8BOM)))
	d.Strict = true
	return d
}
