package app

import (
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Component identity at intake (EDR-IDENTITY-01 D1–D6).
//
// The design principle, and the one sentence the rest follows from: *an unknown ECOSYSTEM is a
// valid state of incomplete knowledge; an empty PURL is not an identity. Manufacture neither.*
//
// The two are routinely conflated and are not the same defect. `FixesFor` already models the
// first correctly — an unknown ecosystem filters nothing, so the drawer shows every fix with the
// confirm-install-method caveat, while `StrictFixesFor` stays fail-CLOSED so no verdict fires.
// Only the missing identity is broken, and it is broken two ways at once: a purl-less component
// is recorded with `component_purl = ''`, which is IN THE PRIMARY KEY (so every purl-less
// component on one release/card collapses onto a single row, merged by the ABSENCE of identity),
// and Governance's domain rejects it, rolling back the inbox transaction and halting the whole
// Knowledge→Governance stream.

// resolutionReason names why an observation could not be resolved. It is operator-facing text,
// not a decision input — nothing branches on it.
const (
	// ReasonNoCandidate — nothing on the release matches this observation's name+version. The
	// common case is a scanner-ONLY release, which has no SBOM and therefore never a twin.
	ReasonNoCandidate = "no_candidate"
	// ReasonAmbiguous — more than one DISTINCT canonical purl matches. Exactly the case where a
	// guess would be wrong, so no tie-break is invented (D2).
	ReasonAmbiguous = "ambiguous"
)

// UnresolvedObservation is a scanner observation that named a component but whose identity could
// not be established. It is RETAINED and COUNTED, never silently discarded and never treated as
// a bystander (D6) — conflating "we could not identify it" with "it does not carry the flaw"
// would make this change cause the very defect EDR-CORRELATION-01 exists to prevent.
//
// The raw identifier rides along for operator display only. It is not persisted: the report's
// bytes stay in `evidence.raw_document`, so the observed string is always recoverable from the
// context that owns it (D5), rather than duplicated into a Knowledge row.
type UnresolvedObservation struct {
	RawPURL   string
	Name      string
	Version   string
	Ecosystem string
	Origin    string
	Reason    string
}

// UsablePURL reports whether a string is an identity rather than merely a name.
//
// It delegates to the kernel value object and never re-implements it: "is this an identity?"
// must have exactly ONE definition, and a second parser would be a second answer. Knowledge did
// not validate purls at all before this (`value.NewPURL` was called only in Evidence), which is
// why `app:httpd` travelled as far as a Governance rejection.
//
// Empty and unparseable deliberately collapse to the same outcome. That is D1's point: an empty
// PURL is not an identity, and neither is a string that merely looks like one.
func UsablePURL(s string) bool {
	_, err := value.NewPURL(strings.TrimSpace(s))
	return err == nil
}

// ResolveIdentity returns the canonical PURL for an observation whose own purl is absent or
// unusable, resolving it onto the release's component that it is a second representation OF.
//
// The rule is deliberately narrow (D2): resolve when EXACTLY ONE candidate matches by
// name+version. More than one, or none, ABSTAINS — the same shape as the D9 apk multi-bound
// abstention, and what makes this a convergence rather than a guess.
//
// Measured basis (2026-09-16): one SPDX document carries the same httpd package twice — once
// LIBRARY with a proper `pkg:rpm/rocky/httpd@…` ref, once APPLICATION with no externalRefs at
// all, same name, same versionInfo. On that input the resolution is exact and loses nothing.
//
// Candidates are matched case-insensitively on name and exactly on version: a distro is
// inconsistent about case and never about a version string, and a looser version comparison here
// would risk resolving onto a DIFFERENT build, which is the one error this must not make.
func ResolveIdentity(obs InventoryComponent, candidates []InventoryComponent) (string, string) {
	name, version := strings.ToLower(strings.TrimSpace(obs.Name)), strings.TrimSpace(obs.Version)
	if name == "" || version == "" {
		// Without both, "the same component" is not expressible — abstain rather than match on
		// a name alone, which would merge every version of a package onto one identity.
		return "", ReasonNoCandidate
	}
	seen := map[string]struct{}{}
	for _, c := range candidates {
		if !UsablePURL(c.PURL) {
			continue // a candidate with no identity cannot lend one
		}
		if strings.ToLower(strings.TrimSpace(c.Name)) != name || strings.TrimSpace(c.Version) != version {
			continue
		}
		seen[strings.TrimSpace(c.PURL)] = struct{}{}
	}
	switch len(seen) {
	case 0:
		return "", ReasonNoCandidate
	case 1:
		for p := range seen {
			return p, ""
		}
	}
	return "", ReasonAmbiguous
}
