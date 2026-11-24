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

// AffectedRef is one thing a CVE says it affects: the product (or package) name and, when the
// source states it, the vendor that ships it. The vendor is what keeps a Go module's last path
// segment honest: "runtime" alone names a hundred products, "go-openapi:runtime" names one.
type AffectedRef struct {
	Vendor  string
	Product string
}

// AffectedRefs reads entries in the source's own shape, "vendor:product[:package]" (an NVD CPE
// vendor and product, a CNA's CVE.org `affected` entry) or a bare "product", into refs: one per
// product or package, with its vendor. Names are normalized; short names and "n/a" are dropped,
// and an "n/a" vendor reads as none. The result is distinct and sorted.
func AffectedRefs(entries []string) []AffectedRef {
	seen := map[AffectedRef]struct{}{}
	for _, e := range entries {
		parts := strings.Split(e, ":")
		vendor, products := "", parts
		if len(parts) > 1 {
			vendor, products = NormalizeProductName(parts[0]), parts[1:]
			if vendor == "n/a" {
				vendor = ""
			}
		}
		for _, p := range products {
			if n := NormalizeProductName(p); len(n) >= minMatchNameLen && n != "n/a" {
				seen[AffectedRef{Vendor: vendor, Product: n}] = struct{}{}
			}
		}
	}
	out := make([]AffectedRef, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Product != out[j].Product {
			return out[i].Product < out[j].Product
		}
		return out[i].Vendor < out[j].Vendor
	})
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

// MatchComponents returns the components a CVE may hit. A component matches when its name or
// its source package equals an affected product after normalization. A path-shaped name (a Go
// module, a scoped npm package) also matches on its LAST segment, but only when the ref's
// vendor is one of its other segments ("github.com/go-openapi/runtime" matches
// "go-openapi:runtime", never a bare or another vendor's "runtime"; a host segment reads
// without its domain, so "golang.org" fits the vendor "golang"). Measured on the VM
// 2026-11-24: the last segment alone matched an unrelated vendor's "runtime" at CVSS 10. One row
// per component, sorted by component name; the first match in sorted order is the one reported.
//
// A leading "lib" is not part of the spelling on either side (VM 2026-11-24: the source said
// "libexpat", the component is "expat"), unless what remains is shorter than a match name.
func MatchComponents(refs []AffectedRef, comps []ComponentRef) []NameMatch {
	if len(refs) == 0 || len(comps) == 0 {
		return nil
	}
	whole := map[string]string{}    // spelling key -> the affected name reported
	byLast := map[string][]string{} // product -> vendors that ship it
	for _, r := range refs {
		p := NormalizeProductName(r.Product)
		if len(p) < minMatchNameLen {
			continue
		}
		if prev, ok := whole[nameKey(p)]; !ok || p < prev {
			whole[nameKey(p)] = p
		}
		if v := NormalizeProductName(r.Vendor); v != "" {
			byLast[p] = append(byLast[p], v)
		}
	}
	found := map[string]string{}
	keep := func(comp, on string) {
		if prev, seen := found[comp]; !seen || on < prev {
			found[comp] = on
		}
	}
	for _, c := range comps {
		for _, cand := range []string{NormalizeProductName(c.Name), NormalizeProductName(c.Source)} {
			if on, ok := whole[nameKey(cand)]; ok && cand != "" {
				keep(c.Name, on)
			}
		}
		segs := strings.Split(c.Name, "/")
		if len(segs) < 2 {
			continue
		}
		last := NormalizeProductName(segs[len(segs)-1])
		others := map[string]struct{}{}
		for _, s := range segs[:len(segs)-1] {
			n := NormalizeProductName(s)
			others[n] = struct{}{}
			if i := strings.Index(n, "."); i > 0 {
				others[n[:i]] = struct{}{}
			}
		}
		for _, v := range byLast[last] {
			if _, ok := others[v]; ok {
				keep(c.Name, v+":"+last)
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

// nameKey is the spelling two names are compared in: the normalized name without a leading
// "lib" when at least minMatchNameLen characters remain ("libexpat" and "expat" read alike;
// "libc" stays "libc").
func nameKey(n string) string {
	if rest, ok := strings.CutPrefix(n, "lib"); ok && len(rest) >= minMatchNameLen {
		return rest
	}
	return n
}
