package parser

import (
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// Identity at the DOCUMENT door (EDR-IDENTITY-01 D2/D4/D6).
//
// A document can name the same package twice and identify it only once. Measured 2026-09-16: one
// SPDX file carries httpd as `primaryPackagePurpose: LIBRARY` with a proper
// `pkg:rpm/rocky/httpd@…` external ref, and again as `APPLICATION` with `supplier: NOASSERTION`
// and no `externalRefs` at all — same name, same versionInfo. The duplicate originates upstream.
//
// Both parsers used to drop the unidentifiable entry with a warning. The INVENTORY that produces
// is right (one httpd, the identified one), but two things were wrong:
//
//   - **A purl-less entry with NO twin is a real component that vanishes.** It never reaches the
//     inventory, so nothing can ever correlate it — a false negative created by a parse rule.
//   - **Its SPDXID was absent from the id→purl map, so every relationship edge touching it was
//     silently dropped too** — including the ownership edges that carry Observed-grade bridge
//     evidence (EDR-VERDICT-01 D3). The duplicate was not merely skipped; it took its graph with it.
//
// Resolving the twin fixes both, and it is the SAME rule the scanner door applies: exactly one
// candidate resolves, anything else abstains. One rule, three doors.

// pendingPackage is a document entry that named a component without identifying it.
type pendingPackage struct {
	// ID is the document-local identifier (SPDXID / bom-ref) whose edges must still resolve.
	ID      string
	Name    string
	Version string
	// RawPURL is what the document offered, if anything — operator-facing only.
	RawPURL string
}

// resolveTwins matches each pending entry against the components the document DID identify.
//
// Exactly one distinct canonical purl for the same name+version → that entry is a second
// representation of an identified component: its id maps onto that purl so its edges survive,
// and no duplicate component is added. Zero or several → ABSTAIN; the entry is returned
// unresolved for counting and surfacing (D6), never guessed at and never synthesized (D3).
//
// Names match case-insensitively and versions exactly: a document is inconsistent about case and
// never about a version string, and a looser version comparison risks resolving onto a DIFFERENT
// build — the one error this must not make.
func resolveTwins(components []domain.Component, pending []pendingPackage) (map[string]value.PURL, []pendingPackage) {
	if len(pending) == 0 {
		return nil, nil
	}
	byKey := map[string]map[string]value.PURL{}
	for _, c := range components {
		key := strings.ToLower(strings.TrimSpace(c.Name)) + "@" + strings.TrimSpace(c.Version)
		if byKey[key] == nil {
			byKey[key] = map[string]value.PURL{}
		}
		byKey[key][c.PURL.String()] = c.PURL
	}

	resolved := map[string]value.PURL{}
	var unresolved []pendingPackage
	for _, p := range pending {
		name, version := strings.ToLower(strings.TrimSpace(p.Name)), strings.TrimSpace(p.Version)
		if name == "" || version == "" {
			// Without both, "the same component" is not expressible. Matching on a name alone
			// would merge every version of a package onto one identity.
			unresolved = append(unresolved, p)
			continue
		}
		candidates := byKey[name+"@"+version]
		if len(candidates) != 1 {
			unresolved = append(unresolved, p)
			continue
		}
		for _, purl := range candidates {
			resolved[p.ID] = purl
		}
	}
	return resolved, unresolved
}

// unresolvedWarning is the operator-facing line for an entry the document named but did not
// identify. It says RETAINED-AND-COUNTED rather than "skipped", because that is the difference
// the change is about: the component is not in the inventory, and that fact is now visible.
func unresolvedWarning(p pendingPackage) string {
	raw := p.RawPURL
	if raw == "" {
		raw = "(none)"
	}
	return fmt.Sprintf(
		"unresolved component identity: name=%s version=%s purl=%s — no single identified twin on this document",
		p.Name, p.Version, raw)
}
