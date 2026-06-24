package vexfeed

import "strings"

// stripAlpineBuildRevision removes Alpine -rN build suffix: 1.35.0-r5 → 1.35.0.
// apk version ordering itself lives in the unified domain engine
// (domain.CompareVersionsEco) — see CR-1.
func stripAlpineBuildRevision(version string) string {
	idx := strings.LastIndex(version, "-r")
	if idx < 0 {
		return version
	}
	suffix := version[idx+2:]
	if suffix == "" {
		return version
	}
	for _, ch := range suffix {
		if ch < '0' || ch > '9' {
			return version
		}
	}
	return version[:idx]
}
