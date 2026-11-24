package domain

import (
	"sort"
	"strings"
)

// The PSIRT early alert (EDR-PSIRT-01, Q1 = (a) name match, owner 2026-11-24) ties a CVE the
// world just published to the products whose components it MAY hit, before the Themis engine
// has filed anything. It is a name match and nothing more: version is ignored, nothing is
// decided, and a false alarm is the accepted direction, because the team assesses next and the
// engine decides. These are the pure rules; the app supplies the names.

// NormalizeProductName is the one spelling both sides are compared in: lower case, trimmed,
// with "_" and spaces read as "-". NVD's CPE products use "_" ("http_server"), package names
// use "-", and a CNA writes whatever it likes.
func NormalizeProductName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == '_' || r == ' ' || r == '\t' }), "-")
}

// minMatchNameLen keeps one- and two-letter names out of the match: "c", "go" or "ui" as an
// affected name would tie a CVE to every component that happens to share it.
const minMatchNameLen = 3

// AffectedNames gathers the names a CVE says it affects: NVD's CPE application products, and
// the CNA's CVE.org `affected` entries, which arrive as "vendor:product[:package]" (the vendor
// alone names no component, so it is used only when it is the whole entry). The result is
// normalized, distinct and sorted.
func AffectedNames(cpeProducts, cnaAffected []string) []string {
	seen := map[string]struct{}{}
	add := func(s string) {
		if n := NormalizeProductName(s); len(n) >= minMatchNameLen && n != "n/a" {
			seen[n] = struct{}{}
		}
	}
	for _, p := range cpeProducts {
		add(p)
	}
	for _, a := range cnaAffected {
		parts := strings.Split(a, ":")
		if len(parts) == 1 {
			add(parts[0])
			continue
		}
		for _, p := range parts[1:] {
			add(p)
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ComponentRef is one component of a product as the match sees it: its name and, for a
// distro package, the source package it was built from ("openssl-libs" from "openssl").
type ComponentRef struct {
	Name   string
	Source string
}

// NameMatch is one component an affected name matched, and the name that matched it.
type NameMatch struct {
	Component string
	MatchedOn string
}

// MatchComponents returns the components whose name, source package, or last path segment
// (a Go module or scoped npm name: "golang.org/x/net" -> "net") equals an affected name after
// normalization. One row per component, sorted by component name; the first affected name in
// sorted order is the one reported.
func MatchComponents(affected []string, comps []ComponentRef) []NameMatch {
	if len(affected) == 0 || len(comps) == 0 {
		return nil
	}
	want := map[string]struct{}{}
	for _, a := range affected {
		if n := NormalizeProductName(a); len(n) >= minMatchNameLen {
			want[n] = struct{}{}
		}
	}
	found := map[string]string{}
	for _, c := range comps {
		for _, cand := range componentNames(c) {
			if _, ok := want[cand]; !ok {
				continue
			}
			if prev, seen := found[c.Name]; !seen || cand < prev {
				found[c.Name] = cand
			}
		}
	}
	out := make([]NameMatch, 0, len(found))
	for comp, on := range found {
		out = append(out, NameMatch{Component: comp, MatchedOn: on})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Component < out[j].Component })
	return out
}

func componentNames(c ComponentRef) []string {
	names := []string{NormalizeProductName(c.Name), NormalizeProductName(c.Source)}
	if i := strings.LastIndex(c.Name, "/"); i >= 0 {
		names = append(names, NormalizeProductName(c.Name[i+1:]))
	}
	return names
}
