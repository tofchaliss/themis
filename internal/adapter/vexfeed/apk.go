package vexfeed

import (
	"strconv"
	"strings"
)

// stripAlpineBuildRevision removes Alpine -rN build suffix: 1.35.0-r5 → 1.35.0
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

// compareAlpineVersion compares apk version strings segment-wise.
func compareAlpineVersion(a, b string) int {
	aParts := splitAlpineParts(a)
	bParts := splitAlpineParts(b)
	max := len(aParts)
	if len(bParts) > max {
		max = len(bParts)
	}
	for i := 0; i < max; i++ {
		var av, bv string
		if i < len(aParts) {
			av = aParts[i]
		}
		if i < len(bParts) {
			bv = bParts[i]
		}
		cmp := compareAlpineSegment(av, bv)
		if cmp != 0 {
			return cmp
		}
	}
	return 0
}

func splitAlpineParts(version string) []string {
	var parts []string
	current := strings.Builder{}
	flush := func() {
		if current.Len() > 0 {
			parts = append(parts, current.String())
			current.Reset()
		}
	}
	for _, ch := range version {
		if ch == '.' || ch == '-' || ch == '_' {
			flush()
			continue
		}
		current.WriteRune(ch)
	}
	flush()
	return parts
}

func compareAlpineSegment(a, b string) int {
	if a == b {
		return 0
	}
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
