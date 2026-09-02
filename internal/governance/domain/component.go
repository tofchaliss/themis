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
	// ClaimClass says WHY this component matched the Faultline: `carrier` (evidence says it
	// carries the flaw), `scope` (it was in a distro advisory's rebuild set, with no such
	// evidence), or empty = unknown. Decided by Knowledge at correlation and carried here
	// (EDR-CORRELATION-01 D3/D5); Governance never re-derives it.
	//
	// Governance keeps every component regardless (D2) — the obligation to replace a superseded
	// build is real. The class governs what a consumer may SAY: an upgrade plan and the AI's
	// grounding use carriers, the posture shows everything.
	ClaimClass string
	// DetectionOrigin says WHICH ENGINE produced this match — `discovery` (feed correlation)
	// or `scanner/<name>` (an uploaded scanner report) — carried in from Knowledge (KN-SCAN-2).
	// Display provenance ONLY: it never enters a decision, a policy, or the AI's grounding;
	// authority lives in the trust class and the source tier, and this field exists precisely
	// so an operator can see the difference without it mattering to governance. "" = unknown
	// (a payload predating the field). Knowledge records matches first-wins, so the value is
	// whoever found the occurrence first.
	DetectionOrigin string
	// The occurrence verdict, MIRRORED from Knowledge (EDR-VERDICT-01 D5) — Governance never
	// re-derives it. `cleared_vendor_fix` says the installed build provably carries the vendor's
	// fix; anything else — including "" from a row predating the field — reads as open, the
	// fail-safe direction. Grade (`observed` | `inferred`) is the evidence strength behind a
	// clearance and Reason its plain-language premise, rendered verbatim by the drawer. This is
	// the machine's "handled"; a human's "handled" is the Position, and the two never mix.
	VerdictState  string
	VerdictGrade  string
	VerdictReason string
}

// VerdictIsOpen reports whether this occurrence must be treated as live. Only the affirmative
// clearance closes it; unknown/missing states are open (EDR-VERDICT-01 D2).
func (c MatchedComponent) VerdictIsOpen() bool { return c.VerdictState != "cleared_vendor_fix" }

// ActsAsCarrier reports whether this component must be treated as carrying the flaw. Unknown
// counts: absence of attribution evidence must never hide a live vulnerability, the same
// fail-safe direction as the range gate's undecidable verdict.
func (c MatchedComponent) ActsAsCarrier() bool { return c.ClaimClass != "scope" }

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
