package report

import (
	"regexp"
	"sort"
	"strings"
)

// Hand-installed software (EDR-INTAKE-01, 2026-10-27 amendment H1–H5).
//
// An RPM inventory cannot see software no package manager owns — a Tomcat unpacked under
// `/var/lib`, an application's JARs under `/opt`. Those are exactly the installs where Nessus's
// upstream version check is RIGHT: nobody backports fixes into a hand-installed Tomcat. Nessus
// names them in its DETECTION plugins ("Apache Tomcat Installed (Linux/Unix)", 0 CVEs): a
// `Path :` block with a `Version :`, the plugin's own CPE, and — on SOME plugins — a mark that
// the path belongs to a package (`Managed by OS : True`, `Associated Package`, `(via package
// manager)`).
//
// The rule that decides is H1, and it ABSTAINS rather than guesses. Measured on a real RHEL 8
// export: 220 path blocks on one host, 27 marked package-owned, 193 unmarked — and 181 of the
// unmarked are under `/usr` with their RPM in plugin 22869 (vim, sqlite, every Python egg).
// "Unmarked = hand-installed" would have invented 180 phantom components per host. A block is a
// hand-installed component only when ALL hold:
//
//  1. it comes from a detection plugin (no CVE) whose name has a detection shape, or from the
//     gem / Python list plugins;
//  2. the block carries no package mark;
//  3. the path is outside the rpm trees (`/usr` except `/usr/local`, `/bin`, `/sbin`, `/lib`,
//     `/lib64`, `/etc`, `/boot`);
//  4. plugin 22869 lists no RPM named like the product.
//
// Everything else is left out and NOT counted on the receipt: the receipt counts packages, and
// an unmarked `/usr` path is a path Themis has no `rpm -qf` for, not a package it refused.

// nessusDetectionProduct reads the product a detection plugin is about from the plugin's name,
// which is the one identity both the `.nessus` export and the CSV carry (the CSV has no CPE
// column). The shapes are Tenable's own naming: "<Product> Installed (<platform>)", "<Product>
// JAR Detection", "<Product> Detection and Identification (<platform>)", "<Product>
// Client/Server Installed (Linux)", "<Product> Local Detection (Linux / Unix)". A name of any
// other shape is not a detection plugin for this rule.
var nessusDetectionProduct = regexp.MustCompile(
	`^(.+?)\s+(?:Local |Client/Server )?(?:Installed|JAR Detection|Detection(?: and Identification)?)(?:\s*\(.*\))?\s*$`)

// nessusGemListPlugin and nessusPythonListPlugin print `name: / version: / path:` triplets for
// every gem and Python distribution found; their ecosystem is the plugin itself.
const (
	nessusGemListPlugin    = "207584"
	nessusPythonListPlugin = "164122"
)

// nessusPackageMark is every way a detection block says "a package owns this path".
var nessusPackageMark = regexp.MustCompile(
	`Managed by OS\s*:\s*True|Associated Package\s*:|\(via package manager\)|Version Source\s*:\s*Package`)

// The two line shapes inside a `Path :` block.
var (
	nessusBlockPath    = regexp.MustCompile(`(?m)^\s*Path\s*:\s*(.+?)\s*$`)
	nessusBlockVersion = regexp.MustCompile(`(?m)^\s*(?:Installed version|Reported version|Version)\s*:\s*(\S+)\s*$`)
	nessusBlockFixed   = regexp.MustCompile(`(?m)^\s*Fixed version\s*:\s*(\S+)`)
	nessusListField    = regexp.MustCompile(`(?m)^\s*(name|version|path)\s*:\s*(.+?)\s*$`)
)

// nessusRPMTrees are the roots the RPM database owns on an Enterprise Linux host. A path under
// one of them with no package mark is undecidable (rule 3), never a hand install.
var nessusRPMTrees = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/etc/", "/boot/"}

// nessusInstall is one hand-installed component as the rule found it.
type nessusInstall struct {
	path, product, version string
	cpe                    string // `cpe:/a:<vendor>:<product>` when the plugin carried one
	ecosystem              string // "gem" / "pypi" from a list plugin, else ""
}

// nessusInstallIndex is one host's hand-installed components, keyed by path, so a vulnerability
// result's `Path :` block can be looked up (H3).
type nessusInstallIndex map[string]nessusInstall

// nessusDetection is the part of a result the install rule reads, in a shape both the XML and
// the CSV reader can fill.
type nessusDetection struct {
	pluginID, pluginName, output string
	cves                         []string
	cpes                         []string
}

// nessusInstalls applies H1 to one host's results. rpmNames is the package list from plugin
// 22869 on the same host (rule 4); a nil list means no package list, which keeps rule 4 vacuous.
func nessusInstalls(items []nessusDetection, rpmNames map[string]struct{}) nessusInstallIndex {
	idx := nessusInstallIndex{}
	for _, it := range items {
		if len(nessusCVEs(it.cves)) > 0 {
			continue // a vulnerability result names a path; it does not establish one (rule 1)
		}
		switch it.pluginID {
		case nessusGemListPlugin, nessusPythonListPlugin:
			eco := "gem"
			if it.pluginID == nessusPythonListPlugin {
				eco = "pypi"
			}
			for _, inst := range nessusListInstalls(it.output, eco) {
				if nessusUnmanagedPath(inst.path, "") && !nessusRPMOwns(rpmNames, inst.product, "") {
					idx[inst.path] = inst
				}
			}
			continue
		}
		m := nessusDetectionProduct.FindStringSubmatch(strings.TrimSpace(it.pluginName))
		if m == nil {
			continue
		}
		product := m[1]
		cpe := ""
		for _, c := range it.cpes {
			if c = strings.TrimSpace(c); strings.HasPrefix(c, "cpe:/a:") {
				cpe = nessusCPEBase(c)
				break
			}
		}
		if strings.Contains(it.output, "reported by the package manager") {
			continue // the plugin says every path below is a package's (SQLite's shape)
		}
		for _, blk := range strings.Split(it.output, "\n\n") {
			p := nessusBlockPath.FindStringSubmatch(blk)
			v := nessusBlockVersion.FindStringSubmatch(blk)
			if p == nil || v == nil {
				continue
			}
			if !nessusUnmanagedPath(p[1], blk) || nessusRPMOwns(rpmNames, product, cpe) {
				continue
			}
			idx[p[1]] = nessusInstall{path: p[1], product: product, version: v[1], cpe: cpe}
		}
	}
	return idx
}

// nessusListInstalls reads the `name: / version: / path:` triplets of a list plugin.
func nessusListInstalls(output, ecosystem string) []nessusInstall {
	var (
		out []nessusInstall
		cur nessusInstall
	)
	for _, m := range nessusListField.FindAllStringSubmatch(output, -1) {
		switch m[1] {
		case "name":
			cur = nessusInstall{product: m[2], ecosystem: ecosystem}
		case "version":
			cur.version = m[2]
		case "path":
			cur.path = m[2]
			if cur.product != "" && cur.version != "" {
				out = append(out, cur)
			}
			cur = nessusInstall{}
		}
	}
	return out
}

// nessusUnmanagedPath is rules 2 and 3: an absolute path, outside the rpm trees, in a block
// that carries no package mark. A "path" that is not a path (`libwebp (via package manager)`)
// fails both.
func nessusUnmanagedPath(path, block string) bool {
	if !strings.HasPrefix(path, "/") || nessusPackageMark.MatchString(block) {
		return false
	}
	if strings.HasPrefix(path, "/usr/local/") {
		return true
	}
	for _, tree := range nessusRPMTrees {
		if strings.HasPrefix(path, tree) {
			return false
		}
	}
	return true
}

// nessusRPMOwns is rule 4: the host's package list names an RPM that is this product. The
// spellings tried are the ones a vendor RPM of the product would carry — the CPE product
// (`tomcat`), the product name hyphenated (`apache-tomcat`), its last word (`tomcat`), and the
// `python3-` / `rubygem-` prefixes for a list-plugin install. A hit means Themis does not know
// who owns the path, and abstains.
func nessusRPMOwns(rpmNames map[string]struct{}, product, cpe string) bool {
	if len(rpmNames) == 0 {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(product))
	candidates := []string{lower, strings.ReplaceAll(lower, " ", "-"), "python3-" + lower, "rubygem-" + lower}
	if words := strings.Fields(lower); len(words) > 1 {
		candidates = append(candidates, words[len(words)-1])
	}
	if cpe != "" {
		if parts := strings.Split(cpe, ":"); len(parts) == 4 {
			candidates = append(candidates, parts[3])
		}
	}
	for _, c := range candidates {
		if _, ok := rpmNames[c]; ok {
			return true
		}
	}
	return false
}

// nessusCPEBase keeps `cpe:/a:<vendor>:<product>` of a CPE 2.2 URI, dropping any version Nessus
// appended, so the H2 table is keyed on the product alone.
func nessusCPEBase(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 4 {
		return ""
	}
	return strings.Join(parts[:4], ":")
}

// nessusRPMNames reads the package NAMES out of plugin 22869's output, lower-cased, for rule 4.
// Only the name is kept: the rule asks "is there an RPM of this product", not which build.
func nessusRPMNames(output string) map[string]struct{} {
	names := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "|")
		if len(fields) < 3 {
			continue
		}
		if name, _, ok := splitNVR(strings.TrimSpace(fields[0])); ok {
			names[strings.ToLower(name)] = struct{}{}
		}
	}
	return names
}

// nessusCPEPURLs is the H2 table: the CPEs whose package-manager identity is known, one line
// per CPE, each a decision. A CPE with no line gets `pkg:generic/<vendor>/<product>`, which
// claims NO ecosystem — honest, and discovered by no feed; such a component is judged by the
// scanner's own findings (H3) until a line is added here. Closed on purpose, like nessusOSes:
// Tomcat has no line because OSV records it under several Maven artifacts, and picking one
// would be a guess.
var nessusCPEPURLs = map[string]string{
	"cpe:/a:postgresql:postgresql_jdbc_driver": "pkg:maven/org.postgresql/postgresql",
	"cpe:/a:apache:commons_text":               "pkg:maven/org.apache.commons/commons-text",
	"cpe:/a:apache:commons_fileupload":         "pkg:maven/commons-fileupload/commons-fileupload",
}

// nessusInstallPURL gives a hand-installed component its purl (H2). A list-plugin install has
// its ecosystem from the plugin; a detection-plugin install needs a CPE to name a vendor and
// product. No CPE means no identity, and the install is not filed.
func nessusInstallPURL(inst nessusInstall) (string, bool) {
	switch inst.ecosystem {
	case "gem", "pypi":
		return "pkg:" + inst.ecosystem + "/" + inst.product + "@" + inst.version, true
	}
	if inst.cpe == "" {
		return "", false
	}
	if base, ok := nessusCPEPURLs[inst.cpe]; ok {
		return base + "@" + inst.version, true
	}
	parts := strings.Split(inst.cpe, ":")
	return "pkg:generic/" + parts[2] + "/" + parts[3] + "@" + inst.version, true
}

// nessusVulnBlocks reads the `Path :` blocks of a vulnerability result (H3): each path with the
// version Nessus compared and the fix it names. A result with no path block (a banner check)
// yields none.
type nessusVulnBlock struct {
	path, version, fixed string
}

func nessusVulnBlocks(output string) []nessusVulnBlock {
	var out []nessusVulnBlock
	for _, blk := range strings.Split(output, "\n\n") {
		p := nessusBlockPath.FindStringSubmatch(blk)
		if p == nil {
			continue
		}
		b := nessusVulnBlock{path: p[1]}
		if v := nessusBlockVersion.FindStringSubmatch(blk); v != nil {
			b.version = v[1]
		}
		if f := nessusBlockFixed.FindStringSubmatch(blk); f != nil {
			b.fixed = f[1]
		}
		out = append(out, b)
	}
	return out
}

// sortedPaths returns an index's paths in a fixed order, for deterministic output.
func (idx nessusInstallIndex) sortedPaths() []string {
	paths := make([]string, 0, len(idx))
	for p := range idx {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}
