package osv

import "strings"

// NormalizeAlpinePackageName maps Alpine SBOM naming conventions to OSV package names.
func NormalizeAlpinePackageName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "so:")
	if strings.HasPrefix(name, "py3-") {
		return "python3-" + strings.TrimPrefix(name, "py3-")
	}
	return name
}

func normalizePackageName(ecosystem, name string) string {
	switch strings.ToLower(ecosystem) {
	case "apk", "alpine":
		return NormalizeAlpinePackageName(name)
	default:
		return name
	}
}
