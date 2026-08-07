package domain

import "sort"

// ReleasePosture is Intelligence's read-only view of Governance's release-scoped Domain
// Projection (EDR-TRUST-01 T10) — the authoritative answer to "what is outstanding on this
// release", assembled by the context that owns it and merely consumed here.
//
// It is a value mirror decoded from Governance's posture JSON, never Governance's aggregate
// (Intelligence owns no truth, D1; no cross-context import).
type ReleasePosture struct {
	ReleaseID string
	Entries   []PostureEntry
}

// PostureEntry is one outstanding (or decided) Finding on the release.
type PostureEntry struct {
	FindingID         string
	CVE               string
	Stance            string
	ResidualPriority  int
	EffectivePriority int
	Components        []PostureComponent
}

// PostureComponent is one release component a Finding was opened for.
type PostureComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
	// Source is the upstream source-package name for distro components; "" for non-distro. It
	// is the name a fix is published under, and therefore the name a remediation action is
	// expressed in (AI-GROUND-1).
	Source string
}

// UpgradeAction is one unit of remediation work: upgrade this package, and these Findings close.
//
// It is a SHAPING of the projection, not a new source (T10 rule 2): every field is reduced from
// entries the projection contained, nothing is introduced. That distinction is what keeps the
// runtime a consumer of the domain rather than a producer of truth, and it is why grounding
// still anchors to the projection rather than to this view (T10 rule 4).
type UpgradeAction struct {
	// Package is the source package to upgrade — the name a fix is published under.
	Package string
	// Ecosystem disambiguates two packages that share a name across ecosystems.
	Ecosystem string
	// InstalledVersions are the versions currently present, deduplicated.
	InstalledVersions []string
	// CVEs are the vulnerabilities this one upgrade would address, worst-first.
	CVEs []string
	// FindingIDs are the Findings it would close — the provenance link back to the projection
	// (T10 rule 3), so every claim in a plan is traceable to a row an authority vouched for.
	FindingIDs []string
	// TopPriority is the highest residual_priority among them: what ordering the plan by impact
	// means in practice.
	TopPriority int
}

// PlanActions groups a release's OUTSTANDING Findings into upgrade actions, worst-first.
//
// This is the whole reason a release-scoped capability is worth having: 231 Findings on a real
// release collapse to roughly a dozen package upgrades, because one module-stream rebuild closes
// nine CVEs at once. Asking a model to rediscover that grouping from 231 rows would be slow,
// expensive and non-deterministic — grouping is a GROUP BY, not reasoning (T10).
//
// Decided Findings (residual_priority 0) are excluded: a Finding somebody has already assessed as
// not_affected is not work, and including it would pad the plan with actions nobody needs to take.
func (p ReleasePosture) PlanActions() []UpgradeAction {
	type acc struct {
		action    UpgradeAction
		cveSeen   map[string]bool
		verSeen   map[string]bool
		cveByPrio map[string]int
	}
	byKey := map[string]*acc{}
	var order []string

	for _, e := range p.Entries {
		if e.ResidualPriority <= 0 {
			continue // already decided — not work
		}
		for _, c := range e.Components {
			pkg := c.Source
			if pkg == "" {
				pkg = c.Name
			}
			if pkg == "" {
				continue // nothing actionable to name
			}
			key := c.Ecosystem + "\x00" + pkg
			a, ok := byKey[key]
			if !ok {
				a = &acc{
					action:    UpgradeAction{Package: pkg, Ecosystem: c.Ecosystem},
					cveSeen:   map[string]bool{},
					verSeen:   map[string]bool{},
					cveByPrio: map[string]int{},
				}
				byKey[key] = a
				order = append(order, key)
			}
			if c.Version != "" && !a.verSeen[c.Version] {
				a.verSeen[c.Version] = true
				a.action.InstalledVersions = append(a.action.InstalledVersions, c.Version)
			}
			if e.CVE != "" && !a.cveSeen[e.CVE] {
				a.cveSeen[e.CVE] = true
				a.action.CVEs = append(a.action.CVEs, e.CVE)
			}
			if e.ResidualPriority > a.cveByPrio[e.CVE] {
				a.cveByPrio[e.CVE] = e.ResidualPriority
			}
			a.action.FindingIDs = append(a.action.FindingIDs, e.FindingID)
			if e.ResidualPriority > a.action.TopPriority {
				a.action.TopPriority = e.ResidualPriority
			}
		}
	}

	out := make([]UpgradeAction, 0, len(order))
	for _, k := range order {
		a := byKey[k]
		// Worst CVE first within an action, so a truncated render still shows the reason the
		// action matters rather than an arbitrary member of the set.
		sort.SliceStable(a.action.CVEs, func(i, j int) bool {
			return a.cveByPrio[a.action.CVEs[i]] > a.cveByPrio[a.action.CVEs[j]]
		})
		out = append(out, a.action)
	}
	// Highest impact first, then most Findings closed, then package name — fully deterministic,
	// so the same projection always yields the same plan and a diff between two runs means the
	// posture changed rather than the ordering wobbled.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TopPriority != out[j].TopPriority {
			return out[i].TopPriority > out[j].TopPriority
		}
		if len(out[i].FindingIDs) != len(out[j].FindingIDs) {
			return len(out[i].FindingIDs) > len(out[j].FindingIDs)
		}
		return out[i].Package < out[j].Package
	})
	return out
}

// OutstandingCount reports how many Findings on the release still need attention.
func (p ReleasePosture) OutstandingCount() int {
	n := 0
	for _, e := range p.Entries {
		if e.ResidualPriority > 0 {
			n++
		}
	}
	return n
}

// Grounds reports whether an evidence citation refers to something in the authoritative
// projection (T8/T10 rule 4) — the release itself, one of its Findings, a CVE it carries, or a
// component PURL it lists.
//
// It anchors to the PROJECTION, never to the shaped UpgradeAction view. A runtime validating
// against its own transformation would be checking the model against something it produced
// itself, so a buggy grouping would be confirmed rather than caught.
func (p ReleasePosture) Grounds(ref string) bool {
	if ref == "" {
		return false
	}
	if ref == p.ReleaseID {
		return true
	}
	for _, e := range p.Entries {
		if ref == e.FindingID || ref == e.CVE {
			return true
		}
		for _, c := range e.Components {
			if ref == c.PURL {
				return true
			}
		}
	}
	return false
}
