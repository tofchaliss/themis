package domain

import (
	"strings"
	"time"
)

// The rebuild policy (EDR-REBUILD-01 D2, D17, D19, D30, D34). It answers one question for one
// Release: is an image rebuild worth asking for now? It is a record with fixed fields, not a
// script, and its evaluation is a pure function: it reads facts that are already recorded and
// changes nothing. Step R1 holds the record and the rule only. Nothing here sends an event or
// starts a build.

// RebuildMode says what happens when the policy counts at least one Finding.
type RebuildMode string

const (
	// RebuildModeOff: no rebuild is asked for.
	RebuildModeOff RebuildMode = "off"
	// RebuildModeAsk: a person is told, and a person starts the build (D5).
	RebuildModeAsk RebuildMode = "ask"
	// RebuildModeAuto: the request is sent without asking.
	RebuildModeAuto RebuildMode = "auto"
)

// rank orders the modes off < ask < auto (D17). An unknown mode ranks with off, so a value this
// code cannot read never allows a build.
func (m RebuildMode) rank() int {
	switch m {
	case RebuildModeAuto:
		return 2
	case RebuildModeAsk:
		return 1
	default:
		return 0
	}
}

// Valid reports whether m is one of the three modes.
func (m RebuildMode) Valid() bool {
	return m == RebuildModeOff || m == RebuildModeAsk || m == RebuildModeAuto
}

// LowestRebuildMode returns the most restrictive of the given modes (D17: the effective mode is
// the lowest of the installation policy, the policy in force and the tag). No modes gives off.
func LowestRebuildMode(modes ...RebuildMode) RebuildMode {
	if len(modes) == 0 {
		return RebuildModeOff
	}
	lowest := modes[0]
	for _, m := range modes[1:] {
		if m.rank() < lowest.rank() {
			lowest = m
		}
	}
	if !lowest.Valid() {
		return RebuildModeOff
	}
	return lowest
}

// Rebuild cool-down bounds. Zero is allowed (no cool-down); a year is far beyond any use and
// only stops a typing mistake.
const (
	RebuildCoolDownDefault = 24 * time.Hour
	RebuildCoolDownMax     = 365 * 24 * time.Hour
)

// RebuildPolicy is the fixed-field record of D2.
type RebuildPolicy struct {
	// FixRequired: count a Finding only when a fixed version is known for its component (D19).
	FixRequired bool
	// SeverityFloor is the lowest severity bucket that counts (an SLA bucket name).
	SeverityFloor string
	// CountKnownExploited: count a known-exploited Finding whatever its severity.
	CountKnownExploited bool
	// SkipDecided: do not count a Finding whose Position is not_affected or accepted_risk.
	SkipDecided bool
	// CarrierOnly: do not count scope-class components; unknown counts as carrier.
	CarrierOnly bool
	// CoolDown is the shortest time between two rebuild requests for one Release (D14).
	CoolDown time.Duration
	// Mode is off, ask or auto.
	Mode RebuildMode
}

// DefaultRebuildPolicy is D2's starting record: a fix is required, the floor is high, known
// exploited counts, decided Findings and scope components do not, 24 hours, and a person is
// asked first.
func DefaultRebuildPolicy() RebuildPolicy {
	return RebuildPolicy{
		FixRequired: true, SeverityFloor: SLABucketHigh, CountKnownExploited: true,
		SkipDecided: true, CarrierOnly: true, CoolDown: RebuildCoolDownDefault, Mode: RebuildModeAsk,
	}
}

// severityRank orders the buckets low < medium < high < critical; 0 is "no bucket".
func severityRank(bucket string) int {
	switch bucket {
	case SLABucketCritical:
		return 4
	case SLABucketHigh:
		return 3
	case SLABucketMedium:
		return 2
	case SLABucketLow:
		return 1
	default:
		return 0
	}
}

// Valid reports whether the record can be stored: a known severity floor, a known mode, and a
// cool-down inside its bounds.
func (p RebuildPolicy) Valid() bool {
	return severityRank(p.SeverityFloor) > 0 && p.Mode.Valid() &&
		p.CoolDown >= 0 && p.CoolDown <= RebuildCoolDownMax
}

// Reasons a component counts (D34 `counted_because`).
const (
	RebuildCountedSeverityFloor  = "severity_floor"
	RebuildCountedKnownExploited = "known_exploited"
)

// RebuildFixVerdict is Knowledge's answer to "is this occurrence below its fixed version" (D30).
// Governance never compares version strings for this policy.
type RebuildFixVerdict string

const (
	// RebuildFixKnown: a fixed version exists for this package in this world, and the release's
	// version is below it.
	RebuildFixKnown RebuildFixVerdict = "known"
	// RebuildFixNone: no fixed version applies to this occurrence.
	RebuildFixNone RebuildFixVerdict = "none"
	// RebuildFixUnknown: the version could not be read or ordered. Unknown is not a known fix.
	RebuildFixUnknown RebuildFixVerdict = "unknown"
)

// RebuildCandidate is one matched component of one open Finding, with the facts the policy
// reads. It is the unit of D34: one entry is one component of one Finding.
type RebuildCandidate struct {
	FindingID FindingID
	CVE       string
	PURL      string
	// Severity is the bucket the policy compares with its floor ("" = no severity evidence).
	Severity       string
	KnownExploited bool
	// Position is the stance in force; "" when the Finding is undecided.
	Position Stance
	// ClaimClass is the component's attribution class; anything but `scope` acts as carrier.
	ClaimClass string
	// Fix is Knowledge's verdict for this occurrence (D30).
	Fix RebuildFixVerdict
}

// RebuildTarget is a candidate the policy counted, with why.
type RebuildTarget struct {
	RebuildCandidate
	CountedBecause []string
}

// RebuildVerdict is the policy's answer for one Release.
type RebuildVerdict struct {
	// Mode is the policy's own mode. The effective mode of a Release also depends on its tags
	// (D17) and is resolved by the caller with LowestRebuildMode.
	Mode RebuildMode
	// Targeted are the counted candidates, in the order given.
	Targeted []RebuildTarget
}

// Worth reports whether a rebuild is worth asking for: the mode is not off and at least one
// candidate counted.
func (v RebuildVerdict) Worth() bool { return v.Mode != RebuildModeOff && len(v.Targeted) > 0 }

// suppressedForRebuild: the stances SkipDecided leaves out (D2).
func suppressedForRebuild(s Stance) bool {
	return s == StanceNotAffected || s == StanceAcceptedRisk
}

// EvaluateRebuild applies the policy to the open candidates of one Release. Pure: no clock, no
// I/O. The cool-down and the open-cycle rule are the caller's (D13, D14); they gate the opening
// of a cycle, not what counts.
func EvaluateRebuild(p RebuildPolicy, candidates []RebuildCandidate) RebuildVerdict {
	out := RebuildVerdict{Mode: p.Mode}
	if !p.Mode.Valid() {
		out.Mode = RebuildModeOff
	}
	floor := severityRank(p.SeverityFloor)
	for _, c := range candidates {
		if p.SkipDecided && suppressedForRebuild(c.Position) {
			continue
		}
		if p.CarrierOnly && strings.TrimSpace(c.ClaimClass) == ClaimScope {
			continue
		}
		if p.FixRequired && c.Fix != RebuildFixKnown {
			continue
		}
		var because []string
		if rank := severityRank(c.Severity); floor > 0 && rank >= floor {
			because = append(because, RebuildCountedSeverityFloor)
		}
		if p.CountKnownExploited && c.KnownExploited {
			because = append(because, RebuildCountedKnownExploited)
		}
		if len(because) == 0 {
			continue
		}
		out.Targeted = append(out.Targeted, RebuildTarget{RebuildCandidate: c, CountedBecause: because})
	}
	return out
}

// RebuildPolicyLevel names where a policy sits (D11): one for the installation, and an optional
// one per Product and per Release. There is no Project level.
type RebuildPolicyLevel string

const (
	RebuildLevelInstallation RebuildPolicyLevel = "installation"
	RebuildLevelProduct      RebuildPolicyLevel = "product"
	RebuildLevelRelease      RebuildPolicyLevel = "release"
)

// Valid reports whether l is one of the three levels.
func (l RebuildPolicyLevel) Valid() bool {
	return l == RebuildLevelInstallation || l == RebuildLevelProduct || l == RebuildLevelRelease
}

// Who set the mode ceiling of a Release (D17).
const (
	RebuildModeSetByInstallation = "installation"
	RebuildModeSetByPolicy       = "policy"
)

// RebuildPolicyInForce is the policy that applies to one Release and the mode its policies
// allow at most.
type RebuildPolicyInForce struct {
	// Policy is the ONE record in force, whole (D11 item 2: never a field-by-field mix).
	Policy RebuildPolicy
	// Level is where that record sits.
	Level RebuildPolicyLevel
	// ModeCeiling is the lowest of the installation policy's mode and the mode of the policy in
	// force (D17 values 1 and 2). The Release's tags can only lower it further (D17 value 3);
	// this function does not read tags.
	ModeCeiling RebuildMode
	// ModeSetBy says which of the two set the ceiling. When both give the same mode the
	// installation is named: it is the ceiling nobody below can lift.
	ModeSetBy string
}

// ResolveRebuildPolicy picks the policy in force for one Release (D11): the Release's own, else
// its Product's, else the installation's. nil means that level has no policy. Pure.
func ResolveRebuildPolicy(installation RebuildPolicy, product, release *RebuildPolicy) RebuildPolicyInForce {
	out := RebuildPolicyInForce{Policy: installation, Level: RebuildLevelInstallation}
	switch {
	case release != nil:
		out.Policy, out.Level = *release, RebuildLevelRelease
	case product != nil:
		out.Policy, out.Level = *product, RebuildLevelProduct
	}
	out.ModeCeiling = LowestRebuildMode(installation.Mode, out.Policy.Mode)
	out.ModeSetBy = RebuildModeSetByInstallation
	if out.Level != RebuildLevelInstallation && out.Policy.Mode.rank() < installation.Mode.rank() {
		out.ModeSetBy = RebuildModeSetByPolicy
	}
	return out
}
