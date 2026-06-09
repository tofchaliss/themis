package osv

import "strings"

// MapEcosystem translates a PURL or feed ecosystem to an OSV API ecosystem name.
// The second return value is false when OSV has no matching ecosystem (caller should skip).
func MapEcosystem(ecosystem string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return "npm", true
	case "maven":
		return "Maven", true
	case "pypi", "python":
		return "PyPI", true
	case "go", "golang":
		return "Go", true
	case "nuget":
		return "NuGet", true
	case "gem", "rubygems":
		return "RubyGems", true
	case "cargo", "crates.io":
		return "crates.io", true
	case "composer", "packagist":
		return "Packagist", true
	case "hex":
		return "Hex", true
	case "pub":
		return "Pub", true
	case "deb", "debian":
		return "Debian", true
	case "apk", "alpine":
		return "Alpine", true
	case "ubuntu":
		return "Ubuntu", true
	default:
		return "", false
	}
}
