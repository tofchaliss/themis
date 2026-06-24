package domain

// CR-3 — finding provenance.
//
// Every correlated finding records WHO found it and WHAT they said, so multiple
// correlation sources reporting the same (component, cve) can be merged by an
// explicit, distro-authoritative precedence instead of "whichever code path ran
// last". Distro vendors backport security fixes, so for apk/rpm packages the
// distro feed's fixed-version verdict outranks OSV.dev and NVD; for application
// ecosystems OSV.dev (ecosystem-precise ranges) outranks NVD CPE.

// Finding source identifiers stored on component_vulnerabilities.source.
const (
	FindingSourceOSV       = "osv"        // OSV.dev live query (apk, npm, …)
	FindingSourceNVD       = "nvd"        // NVD CPE / by-CVE
	FindingSourceDistroOSV = "distro_osv" // Alpine/Rocky/Wolfi OSV bulk feed (CR-4)
	FindingSourceRHSA      = "rhsa"       // Red Hat CSAF advisories (CR-4)
	FindingSourceScanner   = "scanner"    // imported scanner finding (not used; CR-9 = remove)
	FindingSourceCatalog   = "catalog"    // already-cached CVE with no recorded origin
	FindingSourceLegacy    = "legacy"     // pre-provenance rows / backfill default
)

// DefaultFindingSource returns source when set, otherwise the catalog default.
func DefaultFindingSource(source string) string {
	if source == "" {
		return FindingSourceCatalog
	}
	return source
}

// FindingSourcePrecedence ranks a source for a component's ecosystem; higher wins
// a merge of two findings for the same (component, cve). Distro-authoritative:
// for apk/rpm packages the distro feeds outrank OSV.dev and NVD.
func FindingSourcePrecedence(ecosystem, source string) int {
	distro := ClassifyEcosystem(ecosystem) != VersionClassGeneric
	switch source {
	case FindingSourceDistroOSV:
		if distro {
			return 60
		}
		return 26 // distinct from rhsa so distinct sources never tie (order-independent merge)
	case FindingSourceRHSA:
		if distro {
			return 55
		}
		return 25
	case FindingSourceOSV:
		return 40
	case FindingSourceNVD:
		return 30
	case FindingSourceScanner:
		return 15
	case FindingSourceCatalog:
		return 10
	default:
		return 5
	}
}
