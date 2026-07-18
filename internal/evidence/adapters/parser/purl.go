package parser

import (
	"net/url"
	"strings"
)

// ecosystemFromPURL extracts the purl "type" (ecosystem), e.g. "deb" from
// "pkg:deb/debian/openssl@3.0.11". It returns false when no type can be read.
func ecosystemFromPURL(purl string) (string, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok || rest == "" {
		return "", false
	}
	end := len(rest)
	if slash := strings.Index(rest, "/"); slash >= 0 {
		end = slash
	}
	if at := strings.Index(rest[:end], "@"); at >= 0 {
		end = at
	}
	if end == 0 {
		return "", false
	}
	return rest[:end], true
}

// nameVersionFromPURL derives a component name and version from a purl, used as a
// fallback when the source document omits them. Percent-encoded segments are
// decoded so the values match feed records (e.g. "libstdc%2B%2B" -> "libstdc++").
func nameVersionFromPURL(purl string) (name, version string) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", ""
	}
	slash := strings.Index(rest, "/")
	if slash < 0 || slash+1 >= len(rest) {
		return "", ""
	}
	path := rest[slash+1:]
	if at := strings.LastIndex(path, "@"); at >= 0 {
		return decodeSegment(path[:at]), decodeSegment(stripVersionQualifiers(path[at+1:]))
	}
	return decodeSegment(path), ""
}

// stripVersionQualifiers drops purl version qualifiers ("?..." / "#...").
func stripVersionQualifiers(version string) string {
	if i := strings.IndexAny(version, "?#"); i >= 0 {
		return version[:i]
	}
	return version
}

func decodeSegment(s string) string {
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return s
}
