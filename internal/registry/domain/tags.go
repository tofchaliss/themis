package domain

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Tags (EDR-REMEDIATION-01 D7): a small set of free-form labels on a Product, a Project or a
// Release — `team:payments`, `env:prod`, `customer-facing`. They are FILTERS ONLY: they never
// weight priority (a tag that changed ranking would be an unreviewed policy) and Findings carry
// none. A Release shows its Project's and Product's tags too; filters match on that union.

// TagEntity names what a tag set belongs to.
type TagEntity string

const (
	TagProduct TagEntity = "product"
	TagProject TagEntity = "project"
	TagRelease TagEntity = "release"
)

// MaxTags bounds one entity's tag set; MaxTagLength bounds one tag.
const (
	MaxTags      = 20
	MaxTagLength = 64
)

// ErrInvalidTag is returned for a tag outside the allowed alphabet or length, or too many tags.
var ErrInvalidTag = errors.New("registry: invalid tag")

func tagChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune(":._/-", r)
}

// NormalizeTags lower-cases, trims, de-duplicates and sorts a tag set, refusing a tag that is
// empty, longer than MaxTagLength or outside [a-z0-9:._/-], and a set larger than MaxTags.
func NormalizeTags(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" || len(t) > MaxTagLength || strings.IndexFunc(t, func(r rune) bool { return !tagChar(r) }) >= 0 {
			return nil, fmt.Errorf("%w: %q (1–%d characters of a-z 0-9 : . _ / -)", ErrInvalidTag, raw, MaxTagLength)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) > MaxTags {
		return nil, fmt.Errorf("%w: %d tags, at most %d", ErrInvalidTag, len(out), MaxTags)
	}
	sort.Strings(out)
	return out, nil
}

// UnionTags merges tag sets, sorted and de-duplicated (a Release's effective tags).
func UnionTags(sets ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range sets {
		for _, t := range s {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// HasTag reports whether tags carries tag (case-insensitive); an empty tag matches everything.
func HasTag(tags []string, tag string) bool {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" {
		return true
	}
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
