package value

import "strings"

// EL-stream-scoped RPM fixed-verdict logic (EDR-VEX-01 Phase 3). A vendor (Red Hat and its 1:1
// rebuilds) ships a CVE fix per EL stream — openssl-…-16.el8_10 for RHEL 8, …-16.el9_2 for
// RHEL 9. Deciding "the installed build carries the fix" is only sound WITHIN the same EL major:
// comparing a RHEL-8 install against a RHEL-9 fix (or a rolling main-stream install against a
// minor-locked EUS/AUS backport) can yield a false "fixed" that hides a live vulnerability. This
// file scopes the compare to the same EL major; the feed is responsible for only surfacing
// MAIN-stream fixes (it excludes EUS/AUS/E4S/TUS via the advisory CPE). Every uncertain case
// resolves to "not fixed" (stays affected) — a false "fixed" is the only unsafe direction.

// rpmArchSuffixes are the trailing .arch tokens stripped from an RPM NEVRA before comparison.
var rpmArchSuffixes = []string{"x86_64", "noarch", "aarch64", "s390x", "ppc64le", "i686", "src"}

// RPMReleaseMajor extracts the RHEL major from an RPM version or NEVRA's `.elN` release marker
// (e.g. "1.0.2k-16.el8_10" or "openssl-1:1.0.2k-16.el8_10.x86_64" → "8"). Returns "" when there
// is no `.elN` marker, so a non-EL rpm never decides a stream-scoped verdict.
func RPMReleaseMajor(version string) string {
	v := StripVersionQualifiers(strings.TrimSpace(version))
	idx := strings.LastIndex(v, ".el")
	if idx < 0 {
		return ""
	}
	rest := v[idx+len(".el"):]
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	return rest[:i]
}

// RPMFixedByStream reports whether an installed RPM build is at or above a same-EL-stream vendor
// fix — i.e. the installed build carries the backported fix and is NOT affected. It applies only
// to the rpm version class and compares only within the same EL major; a fix in a different
// stream, an install/fix without a resolvable `.elN`, or a non-rpm ecosystem never decides
// "fixed" here (all fail safe toward "affected"). fixedVersions are the reconciled vendor fixes
// (the feed has already excluded EUS/AUS/E4S/TUS backport lines).
func RPMFixedByStream(ecosystem, installed string, fixedVersions []string) bool {
	if ClassifyEcosystem(ecosystem) != VersionClassRPM {
		return false
	}
	instMajor := RPMReleaseMajor(installed)
	if instMajor == "" {
		return false // can't place the install in an EL stream → never claim fixed
	}
	inst := rpmEVR(installed)
	for _, fix := range fixedVersions {
		if RPMReleaseMajor(fix) != instMajor {
			continue // different EL major (or no marker) → not comparable
		}
		if compareRPMVersion(inst, rpmEVR(fix)) >= 0 {
			return true // installed >= same-stream fix → the fix is present
		}
	}
	return false
}

// rpmEVR normalizes an RPM NEVRA or bare version to its epoch:version-release for comparison: it
// strips a trailing .arch and takes the last two hyphen-separated segments (version-release),
// which drops a package-name prefix ("openssl-1:1.0.2k-16.el8" → "1:1.0.2k-16.el8") while
// leaving an already-bare EVR ("1.0.2k-16.el8") unchanged. RPM versions and releases never
// contain a hyphen, so the last-two split is exact for a NEVRA and a no-op for an EVR.
func rpmEVR(nevra string) string {
	s := StripVersionQualifiers(strings.TrimSpace(nevra))
	if i := strings.LastIndex(s, "."); i >= 0 {
		for _, arch := range rpmArchSuffixes {
			if s[i+1:] == arch {
				s = s[:i]
				break
			}
		}
	}
	parts := strings.Split(s, "-")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "-" + parts[len(parts)-1]
	}
	return s
}

// RPMPackageName extracts the package name from an RPM NEVRA ("openssl-1:1.0.2k-16.el8" ->
// "openssl"), returning "" for a bare EVR that names no package.
//
// It is the inverse of rpmEVR: RPM versions and releases never contain a hyphen, so a NEVRA is
// exactly name + "-" + version + "-" + release and the name is everything before the last two
// segments. Two segments alone is a bare EVR, which names nothing.
//
// It exists so a vendor fix expressed as a NEVRA can be ATTRIBUTED to its package. A fix whose
// package is unknown cannot be used to decide about a component (KN-FIX-1) — the association is
// what makes the verdict about the right software.
func RPMPackageName(nevra string) string {
	s := StripVersionQualifiers(strings.TrimSpace(nevra))
	if i := strings.LastIndex(s, "."); i >= 0 {
		for _, arch := range rpmArchSuffixes {
			if s[i+1:] == arch {
				s = s[:i]
				break
			}
		}
	}
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return "" // bare EVR (or unparseable) — names no package
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

// IsRPMModuleStream reports whether a fix version is a MODULE-STREAM rebuild rather than a fix to
// the package itself — RHEL/Rocky modular builds carry a `.module+elN` marker.
//
// The distinction matters because a modular advisory (RHSA for `python38`, `python39`, …) lists
// EVERY RPM rebuilt in that stream as affected-and-fixed, not only the package carrying the flaw.
// A vulnerability database records that faithfully, so a card legitimately attributes a Python
// `tarfile` fix to `python-ply`. Measured on a live estate: five of the top fifteen posture rows
// pinned interpreter CVEs onto unrelated packages this way (KN-MODULE-1).
//
// It is NOT a reason to drop the fix — upgrading the module IS the correct remediation on a
// modular system. It is a reason to label it, and to prefer a package-specific fix when the card
// holds both, so an operator is not told to upgrade python3-ply for a tarfile bug when a direct
// fix exists.
func IsRPMModuleStream(version string) bool {
	return strings.Contains(version, ".module+el")
}
