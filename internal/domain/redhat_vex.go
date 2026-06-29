package domain

import "strings"

// Red Hat VEX overlay (on-demand Security Data API).
//
// Red Hat publishes an authoritative per-CVE, per-RHEL-stream verdict at
// access.redhat.com/hydra/rest/securitydata/cve/{CVE}.json. For an RPM finding it
// answers the question the version math cannot: did the vendor back-port the fix
// (so an el8 build is "Not affected"), and what is the fixed NEVRA for that exact
// stream. RHEL clones (Rocky, Alma) are 1:1 NEVRA rebuilds, so the same verdict
// applies. Themis surfaces this as a VEX overlay signal — visible and
// human-overridable — it never auto-rescopes severity.

// RedHatCVEReport is the parsed Red Hat Security Data API response for one CVE,
// reduced to the fields the VEX overlay needs (produced by adapter/redhat).
type RedHatCVEReport struct {
	CVEID            string
	ThreatSeverity   string // vendor severity word: Low | Moderate | Important | Critical
	CVSS3            string // vendor CVSS v3 base score, when present
	Statement        string // vendor rationale (e.g. why a stream is Not affected)
	PackageStates    []RedHatPackageState
	AffectedReleases []RedHatAffectedRelease
}

// RedHatPackageState is one package_state entry: the vendor's fix posture for a
// package on a product (CPE carries the RHEL stream).
type RedHatPackageState struct {
	PackageName string
	FixState    string // Not affected | Affected | Will not fix | Fix deferred | Under investigation | …
	CPE         string // cpe:/o:redhat:enterprise_linux:8
}

// RedHatAffectedRelease is one affected_release entry: a shipped fix NEVRA for a
// product (CPE carries the RHEL stream).
type RedHatAffectedRelease struct {
	PackageNEVRA string // ncurses-0:6.2-10.20210508.el9_6.2
	CPE          string
	Advisory     string // RHSA-…
}

// RedHatStreamVerdict is Red Hat's verdict for one package on one RHEL stream.
type RedHatStreamVerdict struct {
	Covered     bool   // Red Hat published a verdict for this package+stream
	NotAffected bool   // package_state fix_state == "Not affected" for this stream
	FixState    string // raw vendor fix_state (carried into the justification)
	FixedEVR    string // back-ported fix epoch:version-release from affected_release, if any
	Advisory    string // RHSA that shipped the fix, if any
}

// VerdictForStream resolves Red Hat's verdict for packageName on the given RHEL
// major stream ("8", "9", …) — an EXACT stream match (an el8 build is only
// suppressed by a RHEL-8 "Not affected", never a RHEL-9 one). It combines
// package_state (fix posture) with affected_release (the back-ported fix NEVRA).
func (r RedHatCVEReport) VerdictForStream(packageName, major string) RedHatStreamVerdict {
	if strings.TrimSpace(packageName) == "" || strings.TrimSpace(major) == "" {
		return RedHatStreamVerdict{}
	}
	out := RedHatStreamVerdict{}
	for _, ps := range r.PackageStates {
		if !strings.EqualFold(strings.TrimSpace(ps.PackageName), packageName) {
			continue
		}
		if redHatCPEMajor(ps.CPE) != major {
			continue
		}
		out.Covered = true
		out.FixState = ps.FixState
		if strings.EqualFold(strings.TrimSpace(ps.FixState), "not affected") {
			out.NotAffected = true
		}
	}
	for _, ar := range r.AffectedReleases {
		if redHatCPEMajor(ar.CPE) != major {
			continue
		}
		evr, ok := redHatNEVRAEVR(ar.PackageNEVRA, packageName)
		if !ok {
			continue
		}
		out.Covered = true
		out.FixedEVR = evr
		out.Advisory = ar.Advisory
	}
	return out
}

// redHatCPEMajor extracts the RHEL major from a Red Hat product CPE
// (cpe:/o:redhat:enterprise_linux:8 → "8"; cpe:/a:redhat:rhel_e4s:9.0 → "9").
// Returns "" when no enterprise-linux/RHEL stream is present.
func redHatCPEMajor(cpe string) string {
	cpe = strings.ToLower(strings.TrimSpace(cpe))
	if cpe == "" {
		return ""
	}
	for _, marker := range []string{"enterprise_linux:", "rhel_e4s:", "rhel_eus:", "rhel_aus:", "rhel_tus:"} {
		if i := strings.Index(cpe, marker); i >= 0 {
			rest := cpe[i+len(marker):]
			return leadingDigits(rest)
		}
	}
	return ""
}

// redHatNEVRAEVR returns the epoch:version-release of a Red Hat affected_release
// NEVRA when it names packageName, e.g.
// ("ncurses-0:6.2-10.20210508.el9_6.2", "ncurses") → ("0:6.2-10.20210508.el9_6.2", true).
// Package names may contain hyphens (perl-Time-Local), so it matches the exact
// "name-" prefix rather than splitting on hyphens.
func redHatNEVRAEVR(nevra, packageName string) (string, bool) {
	nevra = strings.TrimSpace(nevra)
	prefix := packageName + "-"
	if len(nevra) <= len(prefix) || !strings.EqualFold(nevra[:len(prefix)], prefix) {
		return "", false
	}
	evr := nevra[len(prefix):]
	// A NEVRA's EVR always begins with a digit (epoch or version), so the name match
	// is exact: "ncurses" does not match "ncurses-libs-0:…" and "perl" does not match
	// "perl-Time-Local-1:…" (the remainder there starts with a letter).
	if evr[0] < '0' || evr[0] > '9' {
		return "", false
	}
	return evr, true
}

// leadingDigits returns the run of digits at the start of s ("9.0" → "9", "8" → "8").
func leadingDigits(s string) string {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	return s[:end]
}
