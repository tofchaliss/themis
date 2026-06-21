package vexfeed

import (
	"fmt"
	"strconv"
	"strings"
)

type parsedPURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
}

func parsePURL(purl string) parsedPURL {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return parsedPURL{}
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return parsedPURL{Type: rest}
	}
	typ := rest[:slash]
	path := rest[slash+1:]
	at := strings.LastIndex(path, "@")
	if at < 0 {
		// namespace/name split for rpm/apk: pkg:rpm/redhat/httpd@ver
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash < 0 {
			return parsedPURL{Type: typ, Name: path}
		}
		return parsedPURL{
			Type:      typ,
			Namespace: path[:lastSlash],
			Name:      path[lastSlash+1:],
		}
	}
	base := path[:at]
	version := stripPURLQualifiers(path[at+1:])
	lastSlash := strings.LastIndex(base, "/")
	if lastSlash < 0 {
		return parsedPURL{Type: typ, Name: base, Version: version}
	}
	return parsedPURL{
		Type:      typ,
		Namespace: base[:lastSlash],
		Name:      base[lastSlash+1:],
		Version:   version,
	}
}

// stripPURLQualifiers removes the PURL qualifier (?key=val) and subpath (#path)
// from a version segment. Real SBOM purls carry these after the version
// (pkg:apk/alpine/curl@8.14.1-r2?arch=x86_64&distro=3.20.2); leaving them in
// would defeat version comparison against clean vendor-advisory purls.
func stripPURLQualifiers(version string) string {
	if i := strings.IndexAny(version, "?#"); i >= 0 {
		return version[:i]
	}
	return version
}

func buildPURL(p parsedPURL) string {
	if p.Type == "" {
		return ""
	}
	path := p.Name
	if p.Namespace != "" {
		path = p.Namespace + "/" + p.Name
	}
	if p.Version != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", p.Type, path, p.Version)
	}
	return fmt.Sprintf("pkg:%s/%s", p.Type, path)
}

// stripErrataRevision removes trailing errata rebuild suffix: -6.el8_5.1 → -6.el8_5
func stripErrataRevision(version string) string {
	parts := strings.Split(version, "-")
	if len(parts) <= 2 {
		return version
	}
	last := parts[len(parts)-1]
	if strings.Contains(last, ".") && len(strings.Split(last, ".")) > 1 {
		// drop last dotted segment when it looks like errata rebuild (.1)
		dotParts := strings.Split(last, ".")
		if len(dotParts) >= 2 {
			parts[len(parts)-1] = strings.Join(dotParts[:len(dotParts)-1], ".")
			return strings.Join(parts, "-")
		}
	}
	return version
}

// compareRPMEVR compares RPM epoch:version-release strings. Returns -1, 0, 1.
func compareRPMEVR(a, b string) int {
	aEpoch, aVer := splitEpoch(a)
	bEpoch, bVer := splitEpoch(b)
	if aEpoch != bEpoch {
		if aEpoch < bEpoch {
			return -1
		}
		return 1
	}
	return compareRelease(aVer, bVer)
}

func splitEpoch(version string) (epoch int, rest string) {
	colon := strings.Index(version, ":")
	if colon < 0 {
		return 0, version
	}
	ep, err := strconv.Atoi(version[:colon])
	if err != nil {
		return 0, version
	}
	return ep, version[colon+1:]
}

func compareRelease(a, b string) int {
	aSegs := strings.Split(a, "-")
	bSegs := strings.Split(b, "-")
	max := len(aSegs)
	if len(bSegs) > max {
		max = len(bSegs)
	}
	for i := 0; i < max; i++ {
		var av, bv string
		if i < len(aSegs) {
			av = aSegs[i]
		}
		if i < len(bSegs) {
			bv = bSegs[i]
		}
		cmp := compareVersionSegment(av, bv)
		if cmp != 0 {
			return cmp
		}
	}
	return 0
}

func compareVersionSegment(a, b string) int {
	if a == b {
		return 0
	}
	// numeric compare when both numeric
	ai, aErr := strconv.Atoi(a)
	bi, bErr := strconv.Atoi(b)
	if aErr == nil && bErr == nil {
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
		return 0
	}
	return strings.Compare(a, b)
}
