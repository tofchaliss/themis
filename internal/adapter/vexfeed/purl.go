package vexfeed

import (
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
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
	version := domain.StripPURLVersionQualifiers(path[at+1:])
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

// stripErrataRevision removes trailing errata rebuild suffix: -6.el8_5.1 → -6.el8_5.
// RPM epoch:version-release ordering itself lives in the unified domain engine
// (domain.CompareVersionsEco) — see CR-1.
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
