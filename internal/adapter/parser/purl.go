package parser

import (
	"fmt"
	"strings"
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
		return path, ""
	}
	return path[:at], path[at+1:]
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
