package domain

import "strings"

// MatchedComponent is one release component that triggered a Finding, carried in from
// Knowledge's ComponentMatched (D1/D5). It is **content/context** on the Finding, never
// part of its identity: one Finding may list several matched components for the same
// (Release, Faultline), all governed as one decision. The PURL is the dedup key.
type MatchedComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
	// Source is the upstream SOURCE-package name for distro components (python3-pyyaml →
	// PyYAML); "" for non-distro. It is the key that joins this component to its published
	// fix, because feeds attribute fixes to the source package while the PURL carries the
	// binary one (AI-GROUND-1).
	Source string
}

// FixKey returns the names this component may be published under, most specific first: the
// source package, then `namespace:name` (Maven's groupId:artifactId), then the bare name.
//
// One component genuinely has several names across naming authorities — Rocky ships binary
// `python3-pyyaml` built from source `PyYAML`; Maven's `pkg:maven/org.eclipse.jetty/jetty-http`
// is published as `org.eclipse.jetty:jetty-http`. Matching on only one of them silently finds
// nothing, which reads as "no fix published" for a component whose fix is right there.
func (c MatchedComponent) FixKeys() []string {
	keys := make([]string, 0, 3)
	if c.Source != "" {
		keys = append(keys, c.Source)
	}
	if ns := purlNamespace(c.PURL); ns != "" && c.Name != "" {
		keys = append(keys, ns+":"+c.Name)
	}
	if c.Name != "" {
		keys = append(keys, c.Name)
	}
	return keys
}

// purlNamespace extracts the namespace from `pkg:type/namespace/name@version`, returning ""
// when the PURL carries no namespace. The distro qualifier (`pkg:rpm/rocky/...`) occupies the
// same slot, which is harmless: an rpm component resolves through Source first, and "rocky:x"
// matches nothing.
func purlNamespace(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	rest := purl[len(prefix):]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return ""
	}
	rest = rest[slash+1:] // drop the type
	slash = strings.Index(rest, "/")
	if slash < 0 {
		return "" // no namespace segment
	}
	return rest[:slash]
}

// validComponent reports an error unless the component carries a non-empty PURL (its
// identity within the Finding).
func validComponent(c MatchedComponent) error {
	if strings.TrimSpace(c.PURL) == "" {
		return errEmptyComponentURL
	}
	return nil
}
