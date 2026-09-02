package domain

import (
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
)

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
	// Fixes are the versions published for this Finding's own components (PLAN-3), used ONLY to
	// recognise a module-stream rebuild (EDR-CORRELATION-01 D8 step 1). They are never presented
	// as upgrade targets.
	Fixes []PostureFix
}

// PostureFix is a published fix version paired with the package it applies to (KN-FIX-1).
type PostureFix struct {
	Package string
	Version string
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
	// ClaimClass is why this component matched: `carrier`, `scope`, or empty = unknown
	// (EDR-CORRELATION-01 D3). Decided by Knowledge; the runtime consumes it and never
	// re-derives it (T10).
	ClaimClass string
	// VerdictState is the occurrence verdict, mirrored from the projection (EDR-VERDICT-01
	// D2/D8): `cleared_vendor_fix` means these files provably carry the vendor's fix already.
	// Anything else — including "" from a row predating the field — reads as open. Like
	// ClaimClass, it is Knowledge's conclusion; the runtime consumes it and never re-derives it.
	VerdictState string
}

// ActsAsCarrier reports whether this component must be treated as carrying the flaw. Unknown
// counts — absence of attribution evidence must never hide a live vulnerability.
func (c PostureComponent) ActsAsCarrier() bool { return c.ClaimClass != "scope" }

// VerdictIsOpen reports whether this occurrence must be treated as live. Only the affirmative
// clearance closes it (EDR-VERDICT-01 D2 — the fail-safe direction).
func (c PostureComponent) VerdictIsOpen() bool { return c.VerdictState != "cleared_vendor_fix" }

// UpgradeAction is one unit of remediation work: upgrade this package, and these Findings close.
//
// It is a SHAPING of the projection, not a new source (T10 rule 2): every field is reduced from
// entries the projection contained, nothing is introduced. That distinction is what keeps the
// runtime a consumer of the domain rather than a producer of truth, and it is why grounding
// still anchors to the projection rather than to this view (T10 rule 4).
type UpgradeAction struct {
	// Package is the source package to upgrade — the name a fix is published under. When several
	// packages ship as one unit it is the first of Packages, and Packages holds them all.
	Package string
	// Packages are every package this single action covers. Usually one. A RHEL/Rocky module
	// stream is the exception: an advisory rebuilds every RPM in the stream, so `perl-Carp`,
	// `perl-Digest`, `perl-Encode` and a dozen more each look like separate work while being one
	// `dnf module update` (KN-MODULE-1). Presenting them as separate steps turned seven of the
	// top fifteen actions into the same task.
	Packages []string
	// Ecosystem disambiguates two packages that share a name across ecosystems.
	Ecosystem string
	// Stream is the module-stream identity behind this action, empty for an ordinary upgrade. It
	// exists so sibling BUILDS of one stream can be folded (EDR-CORRELATION-01 D8 step 1).
	Stream string
	// InstalledVersions are the versions currently present, deduplicated.
	InstalledVersions []string
	// CVEs are the vulnerabilities this one upgrade would address, worst-first.
	CVEs []string
	// FindingIDs are the Findings it would close — the provenance link back to the projection
	// (T10 rule 3), so every claim in a plan is traceable to a row an authority vouched for.
	FindingIDs []string
	// TopPriority is the highest residual_priority among the findings this action closes — the
	// single worst thing it deals with.
	TopPriority int
	// RiskRemoved is the SUM of residual priorities this action closes, and it is what the plan is
	// ordered by (PLAN-2).
	//
	// Neither obvious ordering is right on its own. Sorting by TopPriority is TRIAGE order — "what
	// is most dangerous?" — and it put a step closing 6 findings above one closing 165. Sorting by
	// count ignores severity entirely and would promote a pile of trivia. The sum answers the
	// question a PLAN is actually asked, "what does this buy me?", by weighting every finding it
	// closes by how much of a problem that finding still is. It also degenerates correctly: with
	// one finding per action it IS triage order.
	RiskRemoved int
}

// moduleBuild matches the build marker a distro module-stream rebuild leaves on every RPM it
// produces — `.module+el8.4.0+570+c2eaf144`. Every package rebuilt by one advisory carries the
// SAME marker, which is what makes it a grouping key.
//
// It deliberately captures the whole marker including the EL version, so a fix in el8.4 and a fix
// in el8.5 stay separate actions. That is conservative in the right direction: merging two
// different stream builds would tell an operator one command covers work it does not.
var moduleBuild = regexp.MustCompile(`\.module\+el[0-9.]+\+[0-9]+\+[0-9a-f]+`)

// namedStream matches the explicit `name:stream-version.context` form some vendors publish
// (`python38:3.8-8030020200818121840.4190259b`). Preferred when present because it NAMES the
// stream, which the build marker cannot.
//
// The leading `[a-z]` is load-bearing. An RPM NEVRA is `epoch:version-release`, so
// `0:1-1.module+el8.4.0+570+c2eaf144` structurally matches `name:stream-context` and was parsed
// as the stream "0:1" — collapsing every module build with the same epoch:version into one
// action, including builds from different EL minors. A module name always starts with a letter
// (`python38`, `perl`, `nodejs`); an epoch never does.
//
// This is the same defect as RANGE-PARSE-1 and the CVSS v2 recogniser: a pattern looser than the
// thing it claims to recognise, turning a non-match into a confident wrong answer.
var namedStream = regexp.MustCompile(`^([a-z][a-z0-9_.-]*:[0-9][0-9a-z.]*)-`)

// streamKeyFor returns the module-stream identity of the fix published for one component, or ""
// when the fix is an ordinary package version.
//
// This is EDR-CORRELATION-01 D8 step 1, and it is the ONE piece of that EDR needing no new data:
// the marker was already on the posture's fix list, and mergeSiblings' comment said this was
// impossible only because "the posture deliberately does not carry [the fix version] yet".
// PLAN-3/DASH-2 means it carries it now, so the premise that forced the CVE-set heuristic has
// expired.
//
// Why grouping happens per COMPONENT rather than per package: a package can be fixed by a module
// rebuild for one CVE and by an ordinary upgrade for another (PyYAML is fixed by the python38
// stream for CVE-2020-1747 and by plain 5.1 for CVE-2017-18342). Keying on the package would put
// both in one action and claim a single command closes both.
func streamKeyFor(fixes []PostureFix, pkg string) string {
	for _, f := range fixes {
		if f.Package != pkg {
			continue
		}
		if m := namedStream.FindStringSubmatch(f.Version); m != nil {
			return m[1]
		}
		if m := moduleBuild.FindString(f.Version); m != "" {
			return m
		}
	}
	return ""
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
		findSeen  map[string]bool // PLAN-4: a Finding counts ONCE per action, however many of its components resolve to this package
		pkgSeen   map[string]bool // the packages one action covers — more than one only for a module-stream rebuild
		cveByPrio map[string]int
	}
	byKey := map[string]*acc{}
	var order []string
	// Residual priority by Finding, so a merged action can RECOMPUTE its risk from its deduped
	// Finding set rather than summing its members' totals (PLAN-4).
	prio := map[string]int{}

	for _, e := range p.Entries {
		if e.ResidualPriority <= 0 {
			continue // already decided — not work
		}
		prio[e.FindingID] = e.ResidualPriority
		for _, c := range e.Components {
			// EDR-CORRELATION-01 D6: a plan is ACTION, so it names only the packages that carry
			// the flaw. A `scope` component was rebuilt alongside the fix and telling someone to
			// "upgrade PyYAML" to resolve a CPython CVE is not a task they can carry out.
			//
			// The Finding is NOT dropped — it still appears under whichever package does carry
			// it, and the obligation to replace the superseded build remains on the posture (D2).
			// Unknown counts as carrier, so a card NVD has not enriched behaves exactly as before.
			if !c.ActsAsCarrier() {
				continue
			}
			// EDR-VERDICT-01 D8: a CLEARED occurrence is not work. Its files already carry the
			// vendor's fix, so an action derived from it would send an operator to upgrade
			// something that is done — measured shape: the patched rpm's .egg-info shadow must
			// not add an action while the pip-installed copy beside it still does.
			if !c.VerdictIsOpen() {
				continue
			}
			pkg := c.Source
			if pkg == "" {
				pkg = c.Name
			}
			if pkg == "" {
				continue // nothing actionable to name
			}
			// The grouping world is the CANONICAL ecosystem (EDR-VERDICT-01 D8): scanners and
			// feeds spell one world many ways (`rhel`/`rpm`, `pypi`/`python-pkg`), and keying on
			// the raw spelling split one job into two while "update the RPM" and "upgrade the
			// pip install" — genuinely different work — must stay two.
			world := value.CanonicalEcosystem(c.Ecosystem)
			// A module-stream rebuild is ONE action covering every package it rebuilt
			// (EDR-CORRELATION-01 D8 step 1); anything else is keyed by its own package.
			key := world + "\x00" + pkg
			stream := streamKeyFor(e.Fixes, pkg)
			if stream != "" {
				key = world + "\x00stream\x00" + stream
			}
			a, ok := byKey[key]
			if !ok {
				a = &acc{
					action:    UpgradeAction{Package: pkg, Ecosystem: world, Stream: stream},
					cveSeen:   map[string]bool{},
					verSeen:   map[string]bool{},
					findSeen:  map[string]bool{},
					pkgSeen:   map[string]bool{},
					cveByPrio: map[string]int{},
				}
				byKey[key] = a
				order = append(order, key)
			}
			// Every package the action covers, in first-seen order (deterministic: the posture
			// arrives in a fixed order). For a non-module action this stays a single name.
			if !a.pkgSeen[pkg] {
				a.pkgSeen[pkg] = true
				a.action.Packages = append(a.action.Packages, pkg)
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
			// Once per Finding, not once per component (PLAN-4). CVEs and versions were already
			// deduped above; Findings were not, so a Finding matching several components of one
			// package — a module-stream rebuild, or a CVE hitting 37 perl subpackages — was
			// counted once for each, inflating both the count and the risk it claims to remove.
			if !a.findSeen[e.FindingID] {
				a.findSeen[e.FindingID] = true
				a.action.FindingIDs = append(a.action.FindingIDs, e.FindingID)
				a.action.RiskRemoved += e.ResidualPriority
			}
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
	// Merge BEFORE ordering: a merged action's RiskRemoved is the sum of its members', so ordering
	// first would rank the parts and then silently promote the whole past its neighbours.
	return sortPlan(mergeSiblings(mergeStreamBuilds(out, prio), prio))
}

// sortPlan orders actions by risk removed, then by the single worst item, then by how many
// Findings close, then by name — fully deterministic, so the same projection always yields the
// same plan and a diff between two runs means the posture changed rather than the sort wobbled.
func sortPlan(actions []UpgradeAction) []UpgradeAction {
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].RiskRemoved != actions[j].RiskRemoved {
			return actions[i].RiskRemoved > actions[j].RiskRemoved
		}
		if actions[i].TopPriority != actions[j].TopPriority {
			return actions[i].TopPriority > actions[j].TopPriority
		}
		if len(actions[i].FindingIDs) != len(actions[j].FindingIDs) {
			return len(actions[i].FindingIDs) > len(actions[j].FindingIDs)
		}
		return actions[i].Package < actions[j].Package
	})
	return actions
}

// mergeSiblings folds actions that close EXACTLY the same set of CVEs into one.
//
// Two packages resolved by the identical CVE set are two names for one remediation. On a modular
// distro that is the normal case, not an edge case: a module-stream advisory rebuilds every RPM in
// the stream, so one `dnf module update` surfaced as `perl-Carp`, `perl-Data-Dumper`, `perl-Digest`
// … each "closes 5 findings, worst CVE-2025-40909" — seven of the top fifteen steps, all the same
// task. A plan that reads as fifteen jobs when it is eight is a plan that gets the schedule wrong.
//
// The CVE set is the right key because it needs no data the projection does not already carry.
// Detecting the `.module+el` marker would be more direct but lives on the FIX VERSION, which the
// posture deliberately does not carry yet — and this generalises beyond RPM to any ecosystem where
// one advisory covers several artifacts.
//
// Merging is CONSERVATIVE: sets must match exactly. Two packages sharing four CVEs of five are
// genuinely different work and stay separate, because collapsing them would hide the fifth.
// Merged members share their CVE set, so they overwhelmingly share their FINDINGS too —
// concatenating the id lists and summing the risk counted the same Finding once per sibling.
// Measured on a live release of 120 Findings: the merged perl step claimed to close 160, and the
// plan's fifteen steps claimed 367 in total. A plan whose arithmetic exceeds the thing it is
// planning over is not a rounding error to a reader; it is a reason to disbelieve the plan.
// `prio` supplies each Finding's residual priority so the merged risk is recomputed from the
// deduped set rather than accumulated (PLAN-4).
func mergeSiblings(actions []UpgradeAction, prio map[string]int) []UpgradeAction {
	byCVEs := map[string]int{} // cve-set key → index in out
	seen := map[int]map[string]bool{}
	out := make([]UpgradeAction, 0, len(actions))
	for _, a := range actions {
		key := a.Ecosystem + "\x00" + strings.Join(sortedCopy(a.CVEs), "\x00")
		if i, ok := byCVEs[key]; ok {
			out[i].Packages = append(out[i].Packages, a.Packages...)
			for _, id := range a.FindingIDs {
				if seen[i][id] {
					continue
				}
				seen[i][id] = true
				out[i].FindingIDs = append(out[i].FindingIDs, id)
				out[i].RiskRemoved += prio[id]
			}
			if a.TopPriority > out[i].TopPriority {
				out[i].TopPriority = a.TopPriority
			}
			for _, v := range a.InstalledVersions {
				if !slices.Contains(out[i].InstalledVersions, v) {
					out[i].InstalledVersions = append(out[i].InstalledVersions, v)
				}
			}
			continue
		}
		byCVEs[key] = len(out)
		seen[len(out)] = map[string]bool{}
		for _, id := range a.FindingIDs {
			seen[len(out)][id] = true
		}
		out = append(out, a)
	}
	return out
}

// mergeStreamBuilds folds actions that are REBUILDS OF THE SAME STREAM into one.
//
// Keying on the build marker alone was too conservative and produced the defect it was meant to
// avoid. Measured on a live release: `PyYAML` labelled FOUR separate steps and `python-ply` a
// fifth, because one stream is rebuilt many times over its life and each advisory leaves a
// different marker (`+el8.4.0+570+c2eaf144`, `+el8.5.0+672+ab6eb015`, …). To an operator that reads
// as "upgrade PyYAML" five times with nothing to tell the steps apart.
//
// The original reasoning — "merging el8.4 with el8.5 would claim one command covers work it does
// not" — is backwards for a STREAM. If you are on an old build, a single `dnf module update` moves
// you past every one of those builds at once. They ARE one command.
//
// The identity that survives is the PACKAGE SET: an identical rebuild scope is the same stream.
// Merging stays exact-match, so a rebuild covering {PyYAML} and one covering {PyYAML, python-ply}
// remain separate — different scopes are different work, and collapsing them would hide the
// second package.
func mergeStreamBuilds(actions []UpgradeAction, prio map[string]int) []UpgradeAction {
	byScope := map[string]int{}
	out := make([]UpgradeAction, 0, len(actions))
	for _, a := range actions {
		if a.Stream == "" { // an ordinary upgrade is not a stream rebuild
			out = append(out, a)
			continue
		}
		key := a.Ecosystem + "\x00" + strings.Join(sortedCopy(a.Packages), "\x00")
		if i, ok := byScope[key]; ok {
			// No dedup needed here, and the reason is a property rather than an assumption:
			// streamKeyFor is a function of (Finding, package), so one Finding maps to exactly
			// ONE stream key per package. Two actions sharing a package SET therefore cannot
			// share a Finding, and a dedup branch here would be unreachable code guarding an
			// impossible case. The property itself is asserted by
			// TestPlanActions_NoActionCountsAFindingTwice, which checks it across a whole plan
			// rather than trusting this comment.
			for _, id := range a.FindingIDs {
				out[i].FindingIDs = append(out[i].FindingIDs, id)
				out[i].RiskRemoved += prio[id]
			}
			for _, cve := range a.CVEs {
				if !slices.Contains(out[i].CVEs, cve) {
					out[i].CVEs = append(out[i].CVEs, cve)
				}
			}
			for _, v := range a.InstalledVersions {
				if !slices.Contains(out[i].InstalledVersions, v) {
					out[i].InstalledVersions = append(out[i].InstalledVersions, v)
				}
			}
			if a.TopPriority > out[i].TopPriority {
				out[i].TopPriority = a.TopPriority
			}
			continue
		}
		byScope[key] = len(out)
		out = append(out, a)
	}
	return out
}

func sortedCopy(in []string) []string {
	c := append([]string(nil), in...)
	sort.Strings(c)
	return c
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
// component it lists (by purl, by name, or by source package).
//
// It anchors to the PROJECTION, never to the shaped UpgradeAction view. A runtime validating
// against its own transformation would check the model against something it produced itself, so a
// buggy grouping would be confirmed rather than caught.
//
// The component NAME and SOURCE are grounded, and drawing that line correctly took a live refusal
// to see. They look like the plan's own labels — an action is headed "upgrade PyYAML" — but
// `PyYAML` is `component.source`, a field the projection carries. What the runtime derived is the
// GROUPING; the name is data. Refusing it discarded an otherwise sound plan whose only fault was
// citing the package it was told to reason about. Rule 4 forbids validating against a derived
// VIEW, not against projection fields the view happens to surface.
func (p ReleasePosture) Grounds(ref string) bool {
	if ref == "" {
		return false
	}
	if ref == p.ReleaseID {
		return true
	}
	for _, e := range p.Entries {
		if e.grounds(ref) {
			return true
		}
	}
	return false
}

// grounds reports whether ref names this entry or one of its components — shared by the
// posture's Grounds and the comparison's (comparison.go), so the two can never disagree on
// what counts as a real identifier.
func (e PostureEntry) grounds(ref string) bool {
	if ref == e.FindingID || ref == e.CVE {
		return true
	}
	for _, c := range e.Components {
		if ref == c.PURL || (c.Name != "" && ref == c.Name) || (c.Source != "" && ref == c.Source) {
			return true
		}
	}
	return false
}
