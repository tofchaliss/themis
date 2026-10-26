package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// nessusInventoryVersion is the inventory converter's identity in provenance.
const nessusInventoryVersion = "nessus-inventory@1"

// nessusSoftwarePlugin is "Software Enumeration (SSH)": the plugin whose output is the host's
// installed-package list (EDR-INTAKE-01, 2026-10-26 amendment).
const nessusSoftwarePlugin = "22869"

// nessusOS is one operating system the inventory road maps (P3): how `operating-system` names
// it, the purl namespace and `distro=` name Themis's feeds read, and the vendor string its own
// packages carry. A package from any other vendor is not given an identity.
type nessusOS struct {
	prefix, namespace, distro, vendor string
}

// nessusOSes is closed and ordered on purpose: adding an OS is a decision about which advisories
// its packages are judged against, not a convenience.
var nessusOSes = []nessusOS{
	{prefix: "Red Hat Enterprise Linux", namespace: "redhat", distro: "rhel", vendor: "Red Hat, Inc."},
	{prefix: "Rocky Linux", namespace: "rocky", distro: "rocky", vendor: "Rocky Enterprise Software Foundation"},
	{prefix: "AlmaLinux", namespace: "almalinux", distro: "almalinux", vendor: "AlmaLinux"},
}

// nessusOSRelease reads `<name> release <x.y>` out of the `operating-system` property, which
// Nessus writes as e.g. "Linux Kernel 4.18.0-… on Red Hat Enterprise Linux release 8.10 (Ootpa)".
var nessusOSRelease = regexp.MustCompile(`(Red Hat Enterprise Linux|Rocky Linux|AlmaLinux)[^\n]*? release (\d+(?:\.\d+)?)`)

type nessusInventoryDoc struct {
	Reports []struct {
		Hosts []struct {
			Props []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:",chardata"`
			} `xml:"HostProperties>tag"`
			Items []struct {
				PluginID string `xml:"pluginID,attr"`
				Output   string `xml:"plugin_output"`
			} `xml:"ReportItem"`
		} `xml:"ReportHost"`
	} `xml:"Report"`
}

// cdxDocument is the CycloneDX 1.5 document the inventory road files (P2). Fields are structs
// and slices, never maps, so `encoding/json` writes them in a fixed order and the same source
// bytes always produce the same document (D3).
type cdxDocument struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    cdxMetadata    `json:"metadata"`
	Components  []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string   `json:"timestamp"`
	Tools     cdxTools `json:"tools"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

// nessusInventory turns a `.nessus` export's package list into a CycloneDX SBOM
// (EDR-INTAKE-01, 2026-10-26 amendment P1–P8).
//
// A package line becomes a component only when the host's OS is mapped, the line's vendor is
// that OS's own vendor, and the name-version-release splits (P3). Everything else is counted in
// ComponentsSkipped and left out: a purl namespace is an ecosystem claim, and a guessed one
// would correlate the wrong advisories. Nothing about the host is written (P6).
type nessusInventory struct{}

func (nessusInventory) Version() string { return nessusInventoryVersion }

func (nessusInventory) Convert(body []byte, observedAt time.Time) ([]byte, Stats, error) {
	if !utf8.Valid(body) {
		return nil, Stats{}, fmt.Errorf("%w: the XML body is not valid UTF-8", ErrMalformedBody)
	}
	if root, isXML, err := xmlRoot(body); err != nil {
		return nil, Stats{}, err
	} else if !isXML || root != nessusRoot {
		return nil, Stats{}, fmt.Errorf("%w: a Nessus export is an XML document whose root is <%s>", ErrMalformedBody, nessusRoot)
	}
	var doc nessusInventoryDoc
	if err := newXMLDecoder(body).Decode(&doc); err != nil {
		return nil, Stats{}, fmt.Errorf("%w: the Nessus export does not parse: %v", ErrMalformedBody, err)
	}

	var (
		stats    Stats
		derived  time.Time
		listed   bool
		mappedOS bool
		seen     = map[string]struct{}{}
		kept     []cdxComponent
	)
	for _, r := range doc.Reports {
		for _, h := range r.Hosts {
			props := map[string]string{}
			for _, p := range h.Props {
				props[p.Name] = strings.TrimSpace(p.Value)
			}
			if t := nessusHostTime(nessusHost{Props: h.Props}); t.After(derived) {
				derived = t
			}
			os, release, ok := nessusHostOS(props["operating-system"])
			mappedOS = mappedOS || ok
			for _, it := range h.Items {
				if it.PluginID != nessusSoftwarePlugin {
					continue
				}
				listed = true
				for _, line := range strings.Split(it.Output, "\n") {
					fields := strings.Split(strings.TrimSpace(line), "|")
					if len(fields) < 3 {
						continue // the plugin's header sentence, or a blank line
					}
					c, good := nessusPackageComponent(fields, os, release, ok)
					if !good {
						stats.ComponentsSkipped++
						continue
					}
					if _, dup := seen[c.PURL]; dup {
						continue // the same package on another host of the same build (P6)
					}
					seen[c.PURL] = struct{}{}
					kept = append(kept, c)
				}
			}
		}
	}
	if !listed {
		return nil, Stats{}, fmt.Errorf("%w: the export carries no package list (plugin %s, \"Software Enumeration (SSH)\"); it needs a credentialed scan with that plugin enabled", ErrSourceInvalid, nessusSoftwarePlugin)
	}
	if !mappedOS {
		return nil, Stats{}, fmt.Errorf("%w: no host runs an operating system Themis maps (Red Hat Enterprise Linux, Rocky Linux, AlmaLinux), so no package can be given an identity", ErrSourceInvalid)
	}
	if len(kept) == 0 {
		return nil, Stats{}, fmt.Errorf("%w: the package list names no package from the operating system's own vendor (%d skipped)", ErrEmptyReport, stats.ComponentsSkipped)
	}
	resolved, err := resolveObservedAt(observedAt, derived, "no host carries a parseable HOST_END_TIMESTAMP, HOST_START_TIMESTAMP or HOST_END")
	if err != nil {
		return nil, Stats{}, err
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].PURL < kept[j].PURL })
	name, version, _ := strings.Cut(nessusInventoryVersion, "@")
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	// A purl's `&` stays `&`: the default `\u0026` is valid JSON, but every reader of
	// the filed document — a person included — would see a purl nobody wrote.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cdxDocument{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		Metadata: cdxMetadata{
			Timestamp: resolved.Format(time.RFC3339),
			Tools: cdxTools{Components: []cdxComponent{
				{Type: "application", Name: "themis-" + name, Version: version},
			}},
		},
		Components: kept,
	}); err != nil {
		// Only strings and ints are encoded; there is no input that reaches here.
		return nil, Stats{}, fmt.Errorf("%w: encoding the inventory: %v", ErrSourceInvalid, err)
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), stats, nil
}

// nessusHostOS maps a host's `operating-system` property onto a known OS and its release.
func nessusHostOS(operatingSystem string) (nessusOS, string, bool) {
	m := nessusOSRelease.FindStringSubmatch(operatingSystem)
	if m == nil {
		return nessusOS{}, "", false
	}
	for _, os := range nessusOSes {
		if os.prefix == m[1] {
			return os, m[2], true
		}
	}
	return nessusOS{}, "", false
}

// nessusPackageComponent reads one `name-version-release|epoch installdate|vendor|packager`
// line. The purl's version carries no epoch — the form Nessus's advisory lines use, so a report
// from the same scan resolves onto it — and a numeric epoch rides as the `epoch` qualifier (P3).
func nessusPackageComponent(fields []string, os nessusOS, release string, osMapped bool) (cdxComponent, bool) {
	if !osMapped || strings.TrimSpace(fields[2]) != os.vendor {
		return cdxComponent{}, false
	}
	name, version, ok := splitNVR(strings.TrimSpace(fields[0]))
	if !ok || strings.Contains(version, ":") {
		return cdxComponent{}, false
	}
	purl := "pkg:rpm/" + os.namespace + "/" + name + "@" + version + "?distro=" + os.distro + "-" + release
	if epoch := strings.Fields(fields[1]); len(epoch) > 0 && isDigits(epoch[0]) && epoch[0] != "0" {
		purl += "&epoch=" + epoch[0]
	}
	return cdxComponent{Type: "library", Name: name, Version: version, PURL: purl}, true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
