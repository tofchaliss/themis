package domain

import (
	"errors"
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
	FixedVersions  []string
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
		FixedVersions:  append([]string(nil), facts.FixedVersions...),
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
	f.FixedVersions = append([]string(nil), p.vulnFacts.FixedVersions...)
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
