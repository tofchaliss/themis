package domain

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// ProposalKind selects how the reconciliation rule (D2) folds a Proposal into the
// enterprise view; each kind carries a distinct payload.
type ProposalKind string

const (
	KindVulnFacts     ProposalKind = "vuln-facts"     // severity/CVSS, affected ranges, fixes
	KindExploitSignal ProposalKind = "exploit-signal" // EPSS, KEV, public exploit
	KindApplicability ProposalKind = "applicability"  // vendor VEX affected/not-affected
)

// Valid reports whether k is a recognized proposal kind.
func (k ProposalKind) Valid() bool {
	switch k {
	case KindVulnFacts, KindExploitSignal, KindApplicability:
		return true
	default:
		return false
	}
}

// VulnFacts is a vuln-facts payload: a source's account of severity, score, affected
// package/version ranges, and fix versions.
type VulnFacts struct {
	Severity       value.Severity
	CVSS           value.CVSS
	AffectedRanges []string
	// Fixes are the versions that resolve the vulnerability, each PAIRED WITH THE PACKAGE it
	// applies to.
	//
	// The package matters because one CVE routinely affects many packages — a RHEL module stream
	// advisory can name hundreds — and a bare list of versions cannot say which belongs to which.
	// Flattening them caused KN-FIX-1: a fixed-verdict compared an installed build against
	// another package's fix and silently dropped 31 live vulnerabilities on one release, and a
	// dashboard offered "upgrade python3-ply 3.9 to 0.1.7".
	//
	// Package may be empty when a source does not say (NVD reports fixes without naming the
	// package). An unattributed fix is usable for display but must never satisfy a per-component
	// verdict — see EnterpriseView.FixesFor.
	Fixes []FixedVersion
	// CarrierProducts are the products this source says CARRY the flaw, as opposed to the
	// packages an advisory happens to rebuild alongside them (EDR-CORRELATION-01 D4).
	//
	// Only a source that describes the FLAW can fill this: NVD's CPE configurations, or an OSV
	// record from a non-distro ecosystem. A distro advisory cannot — its package list is
	// shipping scope, and it carries no CVE→package mapping within itself.
	CarrierProducts []string
}

// UnattributedFixes wraps versions a source did not attribute to a package. They remain visible
// as "a fix is published" and can never satisfy a per-component verdict (see
// EnterpriseView.FixesFor), which is the safe reading of "the source did not say".
func UnattributedFixes(versions []string) []FixedVersion {
	if len(versions) == 0 {
		return nil
	}
	out := make([]FixedVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, FixedVersion{Version: v})
	}
	return out
}

// FixVersions is the flat list of fix versions, for display and for "is a fix published?".
// It deliberately drops the package attribution, so nothing deciding about one component may
// use it — that is what FixesFor is for.
func (f VulnFacts) FixVersions() []string {
	if len(f.Fixes) == 0 {
		return nil
	}
	out := make([]string, 0, len(f.Fixes))
	for _, fx := range f.Fixes {
		out = append(out, fx.Version)
	}
	return out
}

// FixedVersion is one remediation: the version that fixes the vulnerability, and the package it
// fixes it in.
type FixedVersion struct {
	Package string // "" when the source did not attribute it
	Version string
	// Ecosystem is the canonical ecosystem key the fix was published FOR ("rpm", "apk", "npm",
	// …; value.CanonicalEcosystem vocabulary), or "" when the source did not say.
	//
	// It exists because a bare (package, version) pair cannot say WHOSE package it fixes
	// (KN-FIX-3): with Alpine and Red Hat bounds on one shared card, a Rocky rpm component was
	// offered an Alpine apk version as "the published fix" — and the same selection feeds the
	// AI grounding, so the mis-attribution rode into recommendations (the AI-GROUND-1 class).
	// A known ecosystem is a filter; an unknown one never excludes (see EnterpriseView.FixesFor).
	Ecosystem string
}

// ExploitSignal is an exploit-signal payload: exploitation likelihood / known status.
type ExploitSignal struct {
	EPSS          float64 // 0.0–1.0 probability
	KEV           bool    // CISA Known-Exploited
	ExploitPublic bool    // a public exploit exists
}

// Applicability is an applicability payload: a vendor VEX statement about a package.
// Whether to honor it for a given release is Governance's decision, not Knowledge's.
type Applicability struct {
	Package       string
	Status        string // e.g. "affected" / "not_affected"
	Justification string
}

// Proposal is one source's non-authoritative input about a CVE (CON-0002): tagged with
// source + observation time + kind, carrying exactly the payload for its kind. Every
// source (feed, AI, human) produces this same shape; reconciliation — not the proposal
// — decides truth. It is immutable once constructed.
type Proposal struct {
	source        string
	observedAt    time.Time
	kind          ProposalKind
	vulnFacts     *VulnFacts
	exploitSignal *ExploitSignal
	applicability *Applicability
}

// sameAs reports whether two VulnFacts carry identical content (KN-PROPOSAL-BLOAT-1). Slices
// compare element-wise and in order: sources emit them in a stable order, so a reordering is
// itself a change worth recording rather than one worth suppressing.
func (f VulnFacts) sameAs(other VulnFacts) bool {
	return f.Severity == other.Severity &&
		f.CVSS == other.CVSS &&
		slices.Equal(f.AffectedRanges, other.AffectedRanges) &&
		slices.Equal(f.Fixes, other.Fixes)
}

func validSourceAndTime(source string, observedAt time.Time) error {
	switch {
	case strings.TrimSpace(source) == "":
		return errors.New("proposal: empty source")
	case observedAt.IsZero():
		return errors.New("proposal: zero observed-at")
	}
	return nil
}

// NewVulnFactsProposal builds a vuln-facts Proposal (defensively copying the ranges).
func NewVulnFactsProposal(source string, observedAt time.Time, facts VulnFacts) (Proposal, error) {
	if err := validSourceAndTime(source, observedAt); err != nil {
		return Proposal{}, err
	}
	if !facts.Severity.Valid() {
		return Proposal{}, errors.New("proposal: invalid severity")
	}
	copyFacts := VulnFacts{
		Severity:       facts.Severity,
		CVSS:           facts.CVSS,
		AffectedRanges: append([]string(nil), facts.AffectedRanges...),
		Fixes:          append([]FixedVersion(nil), facts.Fixes...),
		// Defensive copy like the rest: a caller mutating its slice afterwards must not be able
		// to change a Proposal that has already been recorded. The append-only audit trail is
		// only trustworthy if a recorded Proposal is immutable.
		CarrierProducts: append([]string(nil), facts.CarrierProducts...),
	}
	return Proposal{source: source, observedAt: observedAt.UTC(), kind: KindVulnFacts, vulnFacts: &copyFacts}, nil
}

// NewExploitSignalProposal builds an exploit-signal Proposal.
func NewExploitSignalProposal(source string, observedAt time.Time, sig ExploitSignal) (Proposal, error) {
	if err := validSourceAndTime(source, observedAt); err != nil {
		return Proposal{}, err
	}
	if sig.EPSS < 0 || sig.EPSS > 1 {
		return Proposal{}, errors.New("proposal: EPSS out of range [0,1]")
	}
	s := sig
	return Proposal{source: source, observedAt: observedAt.UTC(), kind: KindExploitSignal, exploitSignal: &s}, nil
}

// NewApplicabilityProposal builds an applicability Proposal.
func NewApplicabilityProposal(source string, observedAt time.Time, app Applicability) (Proposal, error) {
	if err := validSourceAndTime(source, observedAt); err != nil {
		return Proposal{}, err
	}
	if strings.TrimSpace(app.Package) == "" || strings.TrimSpace(app.Status) == "" {
		return Proposal{}, errors.New("proposal: applicability requires package and status")
	}
	a := app
	return Proposal{source: source, observedAt: observedAt.UTC(), kind: KindApplicability, applicability: &a}, nil
}

// Source returns the provenance (feed / AI capability / human) that raised the proposal.
func (p Proposal) Source() string { return p.source }

// ObservedAt returns when the source observed the fact.
func (p Proposal) ObservedAt() time.Time { return p.observedAt }

// Kind returns the proposal kind.
func (p Proposal) Kind() ProposalKind { return p.kind }

// VulnFacts returns the vuln-facts payload and whether this proposal carries one.
func (p Proposal) VulnFacts() (VulnFacts, bool) {
	if p.vulnFacts == nil {
		return VulnFacts{}, false
	}
	f := *p.vulnFacts
	f.AffectedRanges = append([]string(nil), p.vulnFacts.AffectedRanges...)
	f.Fixes = append([]FixedVersion(nil), p.vulnFacts.Fixes...)
	return f, true
}

// ExploitSignal returns the exploit-signal payload and whether this proposal carries one.
func (p Proposal) ExploitSignal() (ExploitSignal, bool) {
	if p.exploitSignal == nil {
		return ExploitSignal{}, false
	}
	return *p.exploitSignal, true
}

// Applicability returns the applicability payload and whether this proposal carries one.
func (p Proposal) Applicability() (Applicability, bool) {
	if p.applicability == nil {
		return Applicability{}, false
	}
	return *p.applicability, true
}
