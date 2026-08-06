package domain

import (
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
)

// TrustPolicy classifies a source by the trust class of the evidence it produces
// (EDR-TRUST-01 T2). Like Precedence, the domain provides only the mechanism — the
// concrete table is injected by the composition root, so "what is this source worth?"
// is answered in exactly one reviewable place instead of being scattered across the
// feed ACLs that happen to build Proposals.
//
// The classifying question is *derivable vs declared*: can this source's output be
// re-derived, or must someone be believed? A feed republishing a public record (OSV
// ranges, EPSS, KEV) is Observed; a vendor stating something about their own build is
// Asserted; an AI capability is Inferred.
type TrustPolicy struct {
	bySource map[string]value.TrustClass
}

// NewTrustPolicy builds a TrustPolicy from a source→class table. Keys are matched
// case-insensitively, mirroring Precedence.
func NewTrustPolicy(bySource map[string]value.TrustClass) TrustPolicy {
	table := make(map[string]value.TrustClass, len(bySource))
	for s, c := range bySource {
		table[strings.ToLower(strings.TrimSpace(s))] = c
	}
	return TrustPolicy{bySource: table}
}

// ClassOf returns the trust class of a source, failing closed to value.TrustAsserted
// for anything unregistered.
//
// Asserted — not Inferred — is the deliberate fail-closed target. Inferred has a
// specific meaning ("produced by non-deterministic reasoning"), so classifying an
// unregistered feed as Inferred would be *semantically wrong*: it would claim a model
// wrote something no model touched, and trust classes carry meaning rather than merely
// a risk level. Mislabelling for safety corrupts the vocabulary. Asserted is honest for
// an unknown source — "someone told us this and we cannot verify it" — and is still
// conservative, because it keeps the source out of the Observed class that deterministic
// auto-acceptance rests on.
//
// An unregistered source is a configuration gap, not a runtime condition to tolerate
// quietly; `TestEveryKnownSourceIsClassified` fails the build when a shipped source is
// missing from the table.
func (p TrustPolicy) ClassOf(source string) value.TrustClass {
	if c, ok := p.bySource[strings.ToLower(strings.TrimSpace(source))]; ok && c.Valid() {
		return c
	}
	return value.TrustAsserted
}
