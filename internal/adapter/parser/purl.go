package parser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

func ecosystemFromPURL(purl string) (string, bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", false
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if rest == "" {
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

func nameVersionFromPURL(purl string) (name, version string) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	slash := strings.Index(rest, "/")
	if slash < 0 || slash+1 >= len(rest) {
		return "", ""
	}
	path := rest[slash+1:]
	at := strings.LastIndex(path, "@")
	if at < 0 {
		return decodePURLSegment(path), ""
	}
	return decodePURLSegment(path[:at]), decodePURLSegment(domain.StripPURLVersionQualifiers(path[at+1:]))
}

// decodePURLSegment percent-decodes a purl path segment (e.g. "libstdc%2B%2B" →
// "libstdc++", "perl-Text-Tabs%2BWrap" → "perl-Text-Tabs+Wrap") so a fallback
// name/version derived from the purl matches feed records. Falls back to the raw
// value when it is not valid percent-encoding.
func decodePURLSegment(s string) string {
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return s
}

func buildPURL(ecosystem, name, version string) string {
	if ecosystem == "" || name == "" {
		return ""
	}
	if version == "" {
		return fmt.Sprintf("pkg:%s/%s", ecosystem, name)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, name, version)
}
