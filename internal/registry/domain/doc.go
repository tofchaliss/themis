// Package domain is the registry supporting context's domain ring: the
// Product → Project → Release structural identity hierarchy (EDR-KERNEL-01 D1;
// Book II §4). Aggregates hold identity + structure only — names, versions,
// membership — never security state, which Governance owns keyed to a Release it
// references. The Release is the governance boundary the rest of Themis points at
// (Evidence's SubjectRef, Governance's Findings/Positions). The ring is pure: it
// depends on nothing but the standard library.
package domain
