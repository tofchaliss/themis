package domain_test

import (
	"slices"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

func entry(fid, cve string, prio int, comps ...domain.PostureComponent) domain.PostureEntry {
	return domain.PostureEntry{FindingID: fid, CVE: cve, ResidualPriority: prio, Components: comps}
}

func rpm(name, source, version string) domain.PostureComponent {
	return domain.PostureComponent{
		PURL: "pkg:rpm/rocky/" + name + "@" + version, Name: name,
		Version: version, Ecosystem: "rpm", Source: source,
	}
}

// The point of a release-scoped capability: many Findings collapse to few actions, because one
// module-stream rebuild closes several CVEs. Measured on a real release, 231 Findings reduce to
// roughly a dozen package upgrades — a grouping a model should never be asked to rediscover.
func TestPlanActions_CollapsesFindingsIntoUpgrades(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		entry("f1", "CVE-2007-4559", 97, rpm("python3-ply", "python-ply", "3.9-9.el8")),
		entry("f2", "CVE-2021-3177", 96, rpm("python3-ply", "python-ply", "3.9-9.el8")),
		entry("f3", "CVE-2019-6446", 95, rpm("python3-pyyaml", "PyYAML", "3.12-12.el8")),
		entry("f4", "CVE-2026-4480", 94, rpm("libsmbclient", "samba", "4.19.4-15.el8_10")),
	}}

	got := p.PlanActions()
	if len(got) != 3 {
		t.Fatalf("actions = %d, want 3 — four Findings, but two share one python-ply upgrade", len(got))
	}
	// Ordered by impact: python-ply carries the worst Finding (97).
	if got[0].Package != "python-ply" || got[0].TopPriority != 97 {
		t.Errorf("first action = %+v, want python-ply at 97", got[0])
	}
	if len(got[0].CVEs) != 2 || len(got[0].FindingIDs) != 2 {
		t.Errorf("python-ply action = %+v, want both CVEs and both Findings", got[0])
	}
	// The SOURCE package names the action, because that is the name a fix is published under —
	// telling an operator to upgrade "python3-pyyaml" to a "PyYAML" version is the AI-GROUND-1
	// mismatch resurfacing in the plan.
	if got[1].Package != "PyYAML" && got[2].Package != "PyYAML" {
		t.Errorf("actions = %+v, want one named by the source package PyYAML", got)
	}
}

// A decided Finding is not work. Including it would pad the plan with actions nobody needs to
// take — and a plan whose items are already done is a plan people stop reading.
func TestPlanActions_ExcludesDecidedFindings(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		entry("f1", "CVE-1", 0, rpm("python3-ply", "python-ply", "3.9")), // decided
		entry("f2", "CVE-2", 50, rpm("libsmbclient", "samba", "4.19.4")),
	}}
	got := p.PlanActions()
	if len(got) != 1 || got[0].Package != "samba" {
		t.Fatalf("actions = %+v, want only the outstanding samba upgrade", got)
	}
	if p.OutstandingCount() != 1 {
		t.Errorf("outstanding = %d, want 1", p.OutstandingCount())
	}
}

// Non-distro components have no source package; the binary name IS the published name.
func TestPlanActions_FallsBackToTheComponentName(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 71, Components: []domain.PostureComponent{
			{PURL: "pkg:pypi/urllib3@1.26.20", Name: "urllib3", Version: "1.26.20", Ecosystem: "pypi"},
		}},
		// A component naming nothing at all is skipped rather than producing a blank action.
		{FindingID: "f2", CVE: "CVE-2", ResidualPriority: 60, Components: []domain.PostureComponent{
			{PURL: "pkg:rpm/rocky/x@1", Ecosystem: "rpm"},
		}},
	}}
	got := p.PlanActions()
	if len(got) != 1 || got[0].Package != "urllib3" {
		t.Fatalf("actions = %+v, want only the named urllib3 upgrade", got)
	}
}

// The plan must be deterministic: the same projection always yields the same ordering, so a diff
// between two runs means the posture changed rather than the sort wobbled.
func TestPlanActions_IsDeterministic(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		entry("f1", "CVE-1", 50, rpm("a", "a-src", "1")),
		entry("f2", "CVE-2", 50, rpm("b", "b-src", "1")),
		entry("f3", "CVE-3", 50, rpm("b", "b-src", "2")),
	}}
	first := p.PlanActions()
	for i := 0; i < 5; i++ {
		got := p.PlanActions()
		for j := range got {
			if got[j].Package != first[j].Package {
				t.Fatalf("run %d differs at %d: %q vs %q", i, j, got[j].Package, first[j].Package)
			}
		}
	}
	// Equal priority → more Findings closed wins.
	if first[0].Package != "b-src" {
		t.Errorf("first = %q, want b-src (closes two Findings at the same priority)", first[0].Package)
	}
}

// Grounding anchors to the PROJECTION, never to the shaped plan (T10 rule 4). A runtime that
// validated against its own transformation would confirm a buggy grouping instead of catching it.
func TestReleasePosture_Grounds(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		entry("f1", "CVE-2007-4559", 97, rpm("python3-ply", "python-ply", "3.9-9.el8")),
	}}
	for _, ref := range []string{
		"rel-1",                               // the release itself
		"f1",                                  // a Finding on it
		"CVE-2007-4559",                       // a CVE it carries
		"pkg:rpm/rocky/python3-ply@3.9-9.el8", // a component purl it lists
	} {
		if !p.Grounds(ref) {
			t.Errorf("Grounds(%q) = false, want true — it is in the projection", ref)
		}
	}
	// The component's NAME and SOURCE ground too. They look like the plan's own labels — an action
	// is headed "upgrade python-ply" — but `python-ply` is `component.source`, a field the
	// projection carries. What the runtime derived is the GROUPING, not the name.
	//
	// This assertion was originally inverted, on the reasoning that a package name is "the
	// runtime's own derivation". A live model then cited `PyYAML (rpm)` and an otherwise sound
	// plan was discarded for naming the package it had been told to reason about. Rule 4 forbids
	// validating against a derived VIEW — not against projection fields that view surfaces.
	for _, ref := range []string{"python-ply", "python3-ply"} {
		if !p.Grounds(ref) {
			t.Errorf("Grounds(%q) = false — it is a component field the projection carries", ref)
		}
	}
	for _, ref := range []string{
		"",                 // an empty citation grounds nothing
		"rel-2",            // a different release
		"CVE-2099-0001",    // a CVE the release does not carry
		"f9",               // a Finding on another release
		"python-ply (rpm)", // a DECORATED name is not a citation: matching is exact, so a model
		// dressing a reference up cannot slip past by accident
		"openssl", // a package this release does not contain
	} {
		if p.Grounds(ref) {
			t.Errorf("Grounds(%q) = true, want false", ref)
		}
	}
}

// One package can be installed at several versions across a release (different images, different
// module streams). The action must list each once — a repeated version reads as more work than
// there is, and a missing one hides a build somebody still has to upgrade.
func TestPlanActions_DeduplicatesInstalledVersions(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		entry("f1", "CVE-1", 90, rpm("python3-ply", "python-ply", "3.9-9.el8")),
		entry("f2", "CVE-2", 80, rpm("python3-ply", "python-ply", "3.9-9.el8")),  // same version again
		entry("f3", "CVE-3", 70, rpm("python3-ply", "python-ply", "3.11-1.el8")), // a second build
	}}
	got := p.PlanActions()
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1", len(got))
	}
	if len(got[0].InstalledVersions) != 2 {
		t.Errorf("installed = %v, want the two distinct builds", got[0].InstalledVersions)
	}
	if len(got[0].CVEs) != 3 || len(got[0].FindingIDs) != 3 {
		t.Errorf("action = %+v, want all three findings counted", got[0])
	}
}

// The last tiebreak: equal priority AND equal finding count. Without it two actions could swap
// places between runs on identical data, and a plan that reorders itself is a plan nobody can
// diff — "did the posture change, or did the sort?" is not a question an operator should have.
func TestPlanActions_TiesBreakOnPackageName(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		entry("f1", "CVE-1", 50, rpm("zlib", "zlib-src", "1")),
		entry("f2", "CVE-2", 50, rpm("acl", "acl-src", "1")),
	}}
	got := p.PlanActions()
	if len(got) != 2 {
		t.Fatalf("actions = %d, want 2", len(got))
	}
	if got[0].Package != "acl-src" || got[1].Package != "zlib-src" {
		t.Errorf("order = %q, %q — want alphabetical when priority and count tie",
			got[0].Package, got[1].Package)
	}
}

// A module-stream advisory rebuilds every RPM in the stream, so one `dnf module update` arrives as
// a dozen packages each closing the identical CVE set. Measured on a live release: seven of the
// top fifteen plan steps were the same task. A plan reading as fifteen jobs when it is eight gets
// the schedule wrong.
func TestPlanActions_MergesPackagesResolvedByTheSameCVEs(t *testing.T) {
	perl := func(name string) domain.PostureComponent {
		return domain.PostureComponent{
			PURL: "pkg:rpm/rocky/" + name + "@1", Name: name, Version: "1", Ecosystem: "rpm", Source: name,
		}
	}
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-2025-40909", ResidualPriority: 60, Components: []domain.PostureComponent{perl("perl-Carp")}},
		{FindingID: "f2", CVE: "CVE-2025-40909", ResidualPriority: 60, Components: []domain.PostureComponent{perl("perl-Digest")}},
		{FindingID: "f3", CVE: "CVE-2025-40909", ResidualPriority: 60, Components: []domain.PostureComponent{{
			PURL: "pkg:rpm/rocky/perl-Encode@2", Name: "perl-Encode", Version: "2",
			Ecosystem: "rpm", Source: "perl-Encode",
		}}},
		// A genuinely separate upgrade, same priority — must NOT be swallowed.
		{FindingID: "f4", CVE: "CVE-2026-1", ResidualPriority: 60, Components: []domain.PostureComponent{perl("samba")}},
	}}

	got := p.PlanActions()
	if len(got) != 2 {
		t.Fatalf("actions = %d, want 2 — the three perl packages are one module update", len(got))
	}
	var merged domain.UpgradeAction
	for _, a := range got {
		if len(a.Packages) > 1 {
			merged = a
		}
	}
	if len(merged.Packages) != 3 {
		t.Fatalf("merged action = %+v, want all three perl packages", merged)
	}
	if len(merged.FindingIDs) != 3 {
		t.Errorf("findings = %d, want 3 — merging must not lose what the step closes", len(merged.FindingIDs))
	}
	// Siblings ship at their own versions, and the merged step must carry each one: an operator
	// reading "installed: 1" for a set that also has a 2 deployed would stop one build short.
	if len(merged.InstalledVersions) != 2 {
		t.Errorf("installed = %v, want both distinct builds across the merged packages", merged.InstalledVersions)
	}
}

// Merging is CONSERVATIVE: the CVE sets must match EXACTLY. Two packages sharing most of their
// CVEs are genuinely different work, and collapsing them would hide the one that differs.
func TestPlanActions_DoesNotMergeOverlappingButUnequalCVESets(t *testing.T) {
	c := func(name string) domain.PostureComponent {
		return domain.PostureComponent{PURL: "pkg:rpm/rocky/" + name + "@1", Name: name, Ecosystem: "rpm", Source: name}
	}
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 50, Components: []domain.PostureComponent{c("a")}},
		{FindingID: "f2", CVE: "CVE-1", ResidualPriority: 50, Components: []domain.PostureComponent{c("b")}},
		{FindingID: "f3", CVE: "CVE-2", ResidualPriority: 40, Components: []domain.PostureComponent{c("b")}}, // b has one more
	}}
	got := p.PlanActions()
	if len(got) != 2 {
		t.Fatalf("actions = %d, want 2 kept separate — b carries a CVE a does not", len(got))
	}
	for _, a := range got {
		if len(a.Packages) != 1 {
			t.Errorf("action %+v merged, but the CVE sets differ", a)
		}
	}
}

// PLAN-2: the plan is ordered by RISK REMOVED, not by the single worst item.
//
// Measured on the VM: triage ordering put a step closing 6 findings above one closing 165. Triage
// order answers "what is most dangerous?"; a plan is asked "what does this buy me?". The sum
// weights every finding an action closes by how much of a problem it still is, and degenerates to
// triage order when each action closes exactly one finding.
func TestPlanActions_OrdersByRiskRemoved(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		// One severe finding: worst single item, but little total risk.
		entry("f1", "CVE-1", 97, rpm("libsmbclient", "samba", "4.19")),
		// Many moderate findings on one package: less severe individually, far more risk removed.
		entry("f2", "CVE-2", 60, rpm("python3-ply", "python-ply", "3.9")),
		entry("f3", "CVE-3", 60, rpm("python3-ply", "python-ply", "3.9")),
		entry("f4", "CVE-4", 60, rpm("python3-ply", "python-ply", "3.9")),
	}}
	got := p.PlanActions()
	if len(got) != 2 {
		t.Fatalf("actions = %d, want 2", len(got))
	}
	if got[0].Package != "python-ply" {
		t.Errorf("first = %q (risk %d), want python-ply — 180 removed beats a single 97",
			got[0].Package, got[0].RiskRemoved)
	}
	if got[0].RiskRemoved != 180 || got[0].TopPriority != 60 {
		t.Errorf("action = %+v, want risk 180 and worst item 60", got[0])
	}
	// It still reports the single worst item, because "removes the most risk" and "contains the
	// scariest thing" are both worth knowing and neither substitutes for the other.
	if got[1].TopPriority != 97 {
		t.Errorf("samba TopPriority = %d, want 97", got[1].TopPriority)
	}
}

// A merged step's risk is the SUM of its members', so merging must happen BEFORE ordering —
// otherwise the parts are ranked and the whole is silently promoted past its neighbours.
func TestPlanActions_MergedStepIsOrderedByItsCombinedRisk(t *testing.T) {
	c := func(name string) domain.PostureComponent {
		return domain.PostureComponent{PURL: "pkg:rpm/rocky/" + name + "@1", Name: name, Ecosystem: "rpm", Source: name}
	}
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		// Two siblings, identical CVE set: 50 + 50 = 100 once merged.
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 50, Components: []domain.PostureComponent{c("httpd")}},
		{FindingID: "f2", CVE: "CVE-1", ResidualPriority: 50, Components: []domain.PostureComponent{c("mod_http2")}},
		// A standalone action that beats either sibling alone (60) but not their sum.
		{FindingID: "f3", CVE: "CVE-9", ResidualPriority: 60, Components: []domain.PostureComponent{c("glibc")}},
	}}
	got := p.PlanActions()
	if len(got) != 2 {
		t.Fatalf("actions = %d, want 2", len(got))
	}
	if len(got[0].Packages) != 2 || got[0].RiskRemoved != 100 {
		t.Errorf("first = %+v, want the merged httpd+mod_http2 step at risk 100", got[0])
	}
}

// The full tiebreak ladder. Ordering must be TOTAL: any two actions have a defined order, so the
// same posture always yields the same plan and a diff between runs means the data changed.
func TestPlanActions_TiebreakLadder(t *testing.T) {
	c := func(name string) domain.PostureComponent {
		return domain.PostureComponent{PURL: "pkg:rpm/rocky/" + name + "@1", Name: name, Ecosystem: "rpm", Source: name}
	}
	mk := func(pkg string, prios ...int) []domain.PostureEntry {
		var out []domain.PostureEntry
		for i, pr := range prios {
			out = append(out, domain.PostureEntry{
				FindingID: pkg + string(rune('a'+i)), CVE: pkg + "-CVE-" + string(rune('a'+i)),
				ResidualPriority: pr, Components: []domain.PostureComponent{c(pkg)},
			})
		}
		return out
	}

	t.Run("equal risk falls through to the single worst item", func(t *testing.T) {
		var e []domain.PostureEntry
		e = append(e, mk("spread", 50, 50)...) // risk 100, worst 50
		e = append(e, mk("sharp", 100)...)     // risk 100, worst 100
		got := domain.ReleasePosture{ReleaseID: "r", Entries: e}.PlanActions()
		if got[0].Package != "sharp" {
			t.Errorf("first = %q, want sharp — same risk, but it contains the worse single item", got[0].Package)
		}
	})

	t.Run("equal risk and worst item falls through to findings closed", func(t *testing.T) {
		var e []domain.PostureEntry
		e = append(e, mk("two", 50, 50)...)       // risk 100, worst 50, 2 findings
		e = append(e, mk("three", 50, 25, 25)...) // risk 100, worst 50, 3 findings
		got := domain.ReleasePosture{ReleaseID: "r", Entries: e}.PlanActions()
		if got[0].Package != "three" {
			t.Errorf("first = %q, want three — same risk and worst item, but it closes more", got[0].Package)
		}
	})

	t.Run("wholly equal actions fall through to the package name", func(t *testing.T) {
		var e []domain.PostureEntry
		e = append(e, mk("zulu", 50)...)
		e = append(e, mk("alpha", 50)...)
		got := domain.ReleasePosture{ReleaseID: "r", Entries: e}.PlanActions()
		if got[0].Package != "alpha" {
			t.Errorf("first = %q, want alpha — identical on every measure, so name decides", got[0].Package)
		}
	})
}

// A merged step reports the worst item across ALL its members, not just the first one folded in.
// Reporting the first would understate a merged step whose danger lives in a later sibling.
func TestPlanActions_MergeCarriesTheWorstItemAcrossSiblings(t *testing.T) {
	c := func(name string) domain.PostureComponent {
		return domain.PostureComponent{PURL: "pkg:rpm/rocky/" + name + "@1", Name: name, Ecosystem: "rpm", Source: name}
	}
	// Identical CVE sets → merged. The SECOND sibling carries the worse finding.
	p := domain.ReleasePosture{ReleaseID: "r", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 10, Components: []domain.PostureComponent{c("aaa")}},
		{FindingID: "f2", CVE: "CVE-1", ResidualPriority: 90, Components: []domain.PostureComponent{c("zzz")}},
	}}
	got := p.PlanActions()
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1 merged", len(got))
	}
	if got[0].TopPriority != 90 {
		t.Errorf("TopPriority = %d, want 90 — the worst item is in the sibling folded in second", got[0].TopPriority)
	}
	if got[0].RiskRemoved != 100 {
		t.Errorf("RiskRemoved = %d, want 100", got[0].RiskRemoved)
	}
}

// PLAN-4 — a Finding must count ONCE per action, however many of its components resolve to that
// action's package, and once across a merge, however many siblings close it.
//
// Measured on a live release of 120 Findings: the merged perl step claimed to close 160, and the
// plan's fifteen steps claimed 367 between them. Both inflations were real double counts. CVEs
// and installed versions were already deduped in the same loop; Findings were not — which is why
// this went unnoticed, since every OTHER number in the action was right.
//
// A plan whose arithmetic exceeds the thing it plans over does not read as an off-by-N to a human.
// It reads as a reason to disbelieve the plan, including the parts that were correct.
func TestPlanActions_CountsEachFindingOncePerAction(t *testing.T) {
	// One CVE hitting many subpackages of one source package — the module-stream case.
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		entry("f1", "CVE-2026-42496", 70,
			rpm("perl-Carp", "perl", "1.42-396.el8"),
			rpm("perl-Encode", "perl", "3.08-461.el8"),
			rpm("perl-Errno", "perl", "1.28-421.el8"),
		),
	}}
	got := p.PlanActions()
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1 — three components, one source package", len(got))
	}
	if n := len(got[0].FindingIDs); n != 1 {
		t.Errorf("FindingIDs = %d (%v), want 1 — one Finding, counted once", n, got[0].FindingIDs)
	}
	if got[0].RiskRemoved != 70 {
		t.Errorf("RiskRemoved = %d, want 70 — not 210, which is the same Finding three times", got[0].RiskRemoved)
	}
}

func TestPlanActions_MergedSiblingsDoNotDoubleCountSharedFindings(t *testing.T) {
	// Two packages closed by the identical CVE set — so mergeSiblings folds them — that close the
	// SAME two Findings. The merged step must report those two Findings, not four.
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		entry("f1", "CVE-A", 70, rpm("perl-Carp", "perl-Carp", "1.42"), rpm("perl-Digest", "perl-Digest", "1.20")),
		entry("f2", "CVE-B", 30, rpm("perl-Carp", "perl-Carp", "1.42"), rpm("perl-Digest", "perl-Digest", "1.20")),
	}}
	got := p.PlanActions()
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1 merged step", len(got))
	}
	if n := len(got[0].FindingIDs); n != 2 {
		t.Errorf("FindingIDs = %d (%v), want 2 — the merge must not repeat a shared Finding", n, got[0].FindingIDs)
	}
	// Recomputed from the deduped set, not summed across members (70+30, not 2x(70+30)).
	if got[0].RiskRemoved != 100 {
		t.Errorf("RiskRemoved = %d, want 100 — summing members double-counts shared Findings", got[0].RiskRemoved)
	}
	// Ordering rests on RiskRemoved, so an inflated sum does not merely misreport — it can put
	// the wrong step first.
	if got[0].TopPriority != 70 {
		t.Errorf("TopPriority = %d, want 70", got[0].TopPriority)
	}
}

// EDR-CORRELATION-01 D8 step 1 — a module-stream rebuild is ONE action, not one per package.
//
// Measured on a live release: a single advisory rebuilt 23 packages (babel, Cython, mod_wsgi,
// numpy, scipy … and PyYAML), and the plan presented them as separate jobs. They are one
// `dnf module update`. The signal is the build marker every RPM from that rebuild carries.
func TestPlanActions_GroupsAModuleStreamRebuildIntoOneAction(t *testing.T) {
	mod := func(pkg string) domain.PostureFix {
		return domain.PostureFix{Package: pkg, Version: "0:1.0-1.module+el8.4.0+570+c2eaf144"}
	}
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-2023-24329", ResidualPriority: 70,
			Components: []domain.PostureComponent{
				rpm2("python3-pyyaml", "PyYAML", "3.12"),
				rpm2("python3-babel", "babel", "2.5"),
				rpm2("python3-numpy", "numpy", "1.17"),
			},
			Fixes: []domain.PostureFix{mod("PyYAML"), mod("babel"), mod("numpy")}},
	}}
	got := p.PlanActions()
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1 — three packages, one module rebuild: %+v", len(got), got)
	}
	if len(got[0].Packages) != 3 {
		t.Errorf("Packages = %v, want all three named so each stays citable (PLAN-6)", got[0].Packages)
	}
	if len(got[0].FindingIDs) != 1 || got[0].RiskRemoved != 70 {
		t.Errorf("action = %+v, want one Finding at 70 — the same Finding must not count per package", got[0])
	}
}

// The same package can be fixed by a module rebuild for one CVE and by an ordinary upgrade for
// another — PyYAML is fixed by the python38 stream for CVE-2020-1747 and by plain 5.1 for
// CVE-2017-18342. Keying on the PACKAGE would merge them and claim one command closes both.
func TestPlanActions_SamePackageSplitsWhenOnlyOneFixIsAModuleRebuild(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-2020-1747", ResidualPriority: 70,
			Components: []domain.PostureComponent{rpm2("python3-pyyaml", "PyYAML", "3.12")},
			Fixes:      []domain.PostureFix{{Package: "PyYAML", Version: "0:5.3.1-1.module+el8.4.0+570+c2eaf144"}}},
		{FindingID: "f2", CVE: "CVE-2017-18342", ResidualPriority: 60,
			Components: []domain.PostureComponent{rpm2("python3-pyyaml", "PyYAML", "3.12")},
			Fixes:      []domain.PostureFix{{Package: "PyYAML", Version: "5.1"}}},
	}}
	got := p.PlanActions()
	if len(got) != 2 {
		t.Fatalf("actions = %d, want 2 — one module rebuild and one ordinary upgrade: %+v", len(got), got)
	}
}

// Two DIFFERENT stream builds stay separate: merging el8.4 with el8.5 would tell an operator one
// command covers work it does not. Conservative in the same direction as mergeSiblings.
func TestPlanActions_DifferentModuleBuildsDoNotMerge(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 70,
			Components: []domain.PostureComponent{rpm2("python3-a", "a", "1")},
			Fixes:      []domain.PostureFix{{Package: "a", Version: "0:1-1.module+el8.4.0+570+c2eaf144"}}},
		{FindingID: "f2", CVE: "CVE-2", ResidualPriority: 60,
			Components: []domain.PostureComponent{rpm2("python3-b", "b", "1")},
			Fixes:      []domain.PostureFix{{Package: "b", Version: "0:1-1.module+el8.5.0+672+ab6eb015"}}},
	}}
	if got := p.PlanActions(); len(got) != 2 {
		t.Errorf("actions = %d, want 2 — different stream builds are different work: %+v", len(got), got)
	}
}

func rpm2(name, source, version string) domain.PostureComponent {
	return domain.PostureComponent{
		PURL: "pkg:rpm/rocky/" + name + "@" + version, Name: name,
		Version: version, Ecosystem: "rpm", Source: source,
	}
}

// EDR-CORRELATION-01 D8.1, second attempt — sibling BUILDS of one stream are one action.
//
// Keying on the build marker alone was too conservative and produced the very defect it meant to
// avoid. Measured on a live release: PyYAML labelled FOUR separate steps, because one stream is
// rebuilt many times over its life and every advisory leaves a different marker. To an operator
// that reads as "upgrade PyYAML" five times with nothing to tell the steps apart.
//
// The original reasoning — "merging el8.4 with el8.5 claims one command covers work it does not" —
// is backwards for a stream: from an old build, ONE `dnf module update` moves you past all of them.
func TestPlanActions_FoldsSiblingBuildsOfOneStream(t *testing.T) {
	fix := func(pkg, marker string) domain.PostureFix {
		return domain.PostureFix{Package: pkg, Version: "0:1-1.module+el" + marker}
	}
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 70,
			Components: []domain.PostureComponent{rpm2("python3-pyyaml", "PyYAML", "3.12")},
			Fixes:      []domain.PostureFix{fix("PyYAML", "8.4.0+570+c2eaf144")}},
		{FindingID: "f2", CVE: "CVE-2", ResidualPriority: 30,
			Components: []domain.PostureComponent{rpm2("python3-pyyaml", "PyYAML", "3.12")},
			Fixes:      []domain.PostureFix{fix("PyYAML", "8.5.0+672+ab6eb015")}},
		{FindingID: "f3", CVE: "CVE-3", ResidualPriority: 20,
			Components: []domain.PostureComponent{rpm2("python3-pyyaml", "PyYAML", "3.12")},
			Fixes:      []domain.PostureFix{fix("PyYAML", "8.9.0+1531+a18208f5")}},
	}}
	got := p.PlanActions()
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1 — three builds of one stream are one `dnf module update`: %+v", len(got), got)
	}
	if len(got[0].FindingIDs) != 3 || got[0].RiskRemoved != 120 {
		t.Errorf("action = %+v, want 3 Findings and risk 120", got[0])
	}
}

// Merging stays EXACT-MATCH on the package set. A rebuild covering {PyYAML} and one covering
// {PyYAML, python-ply} are different scopes and stay separate — collapsing them would hide the
// second package from the operator.
func TestPlanActions_DifferentRebuildScopesStaySeparate(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 70,
			Components: []domain.PostureComponent{rpm2("python3-pyyaml", "PyYAML", "3.12")},
			Fixes:      []domain.PostureFix{{Package: "PyYAML", Version: "0:1-1.module+el8.4.0+570+c2eaf144"}}},
		{FindingID: "f2", CVE: "CVE-2", ResidualPriority: 30,
			Components: []domain.PostureComponent{
				rpm2("python3-pyyaml", "PyYAML", "3.12"), rpm2("python3-ply", "python-ply", "3.9")},
			Fixes: []domain.PostureFix{
				{Package: "PyYAML", Version: "0:1-1.module+el8.5.0+672+ab6eb015"},
				{Package: "python-ply", Version: "0:1-1.module+el8.5.0+672+ab6eb015"}}},
	}}
	if got := p.PlanActions(); len(got) != 2 {
		t.Errorf("actions = %d, want 2 — different rebuild scopes are different work: %+v", len(got), got)
	}
}

// The merge's bookkeeping, exercised where it actually bites: a Finding closed by TWO builds of
// one stream must count once (PLAN-4 again, one level up), a worse item arriving in a later build
// must raise TopPriority, and a second installed version must be recorded without duplicating a
// CVE both builds address.
func TestPlanActions_StreamMergeBookkeeping(t *testing.T) {
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		// f1 matches TWO components of the same package at different installed versions, and its
		// fixes come from two different builds — so it reaches the merge twice.
		{FindingID: "f1", CVE: "CVE-SHARED", ResidualPriority: 40,
			Components: []domain.PostureComponent{
				rpm2("python3-pyyaml", "PyYAML", "3.12"),
				rpm2("python38-pyyaml", "PyYAML", "5.0"),
			},
			Fixes: []domain.PostureFix{{Package: "PyYAML", Version: "0:1-1.module+el8.4.0+570+c2eaf144"}}},
		// A later build carrying a WORSE item, plus the same CVE again.
		{FindingID: "f2", CVE: "CVE-SHARED", ResidualPriority: 90,
			Components: []domain.PostureComponent{rpm2("python3-pyyaml", "PyYAML", "3.12")},
			Fixes:      []domain.PostureFix{{Package: "PyYAML", Version: "0:1-1.module+el8.9.0+1531+a18208f5"}}},
	}}
	got := p.PlanActions()
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1: %+v", len(got), got)
	}
	a := got[0]
	if len(a.FindingIDs) != 2 || a.RiskRemoved != 130 {
		t.Errorf("findings=%v risk=%d, want 2 findings and 130 — f1 must not count twice", a.FindingIDs, a.RiskRemoved)
	}
	if a.TopPriority != 90 {
		t.Errorf("TopPriority = %d, want 90 — a worse item in a later build must raise it", a.TopPriority)
	}
	if len(a.CVEs) != 1 {
		t.Errorf("CVEs = %v, want the shared CVE recorded once", a.CVEs)
	}
	if len(a.InstalledVersions) != 2 {
		t.Errorf("InstalledVersions = %v, want both recorded", a.InstalledVersions)
	}
}

// The property mergeStreamBuilds relies on instead of a dedup branch: no action counts a Finding
// twice. Asserted across a whole plan rather than trusted from a comment, and checked on a shape
// that exercises every merge path — sibling builds, a shared package set, and multi-component
// Findings.
func TestPlanActions_NoActionCountsAFindingTwice(t *testing.T) {
	mod := func(pkg, marker string) domain.PostureFix {
		return domain.PostureFix{Package: pkg, Version: "0:1-1.module+el" + marker}
	}
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 70,
			Components: []domain.PostureComponent{
				rpm2("python3-pyyaml", "PyYAML", "3.12"), rpm2("python38-pyyaml", "PyYAML", "5.0")},
			Fixes: []domain.PostureFix{mod("PyYAML", "8.4.0+570+c2eaf144")}},
		{FindingID: "f2", CVE: "CVE-2", ResidualPriority: 50,
			Components: []domain.PostureComponent{rpm2("python3-pyyaml", "PyYAML", "9.9")},
			Fixes:      []domain.PostureFix{mod("PyYAML", "8.9.0+1531+a18208f5")}},
		// A DIFFERENT rebuild (its own marker), so it forms its own single-package action. Giving
		// it f1's marker would put python-ply and PyYAML in one rebuild scope — correct behaviour,
		// but it would leave two differently-scoped actions both labelled "PyYAML" and this test
		// would be asserting against whichever it happened to pick.
		{FindingID: "f3", CVE: "CVE-3", ResidualPriority: 30,
			Components: []domain.PostureComponent{rpm2("python3-ply", "python-ply", "3.9")},
			Fixes:      []domain.PostureFix{mod("python-ply", "8.6.0+843+5a13dac3")}},
	}}
	for _, a := range p.PlanActions() {
		seen := map[string]bool{}
		for _, id := range a.FindingIDs {
			if seen[id] {
				t.Errorf("action %q counts Finding %s twice: %+v", a.Package, id, a)
			}
			seen[id] = true
		}
	}
	// The two PyYAML builds fold, and the later build's installed version is carried across.
	var py domain.UpgradeAction
	for _, a := range p.PlanActions() {
		if a.Package == "PyYAML" {
			py = a
		}
	}
	if len(py.FindingIDs) != 2 || py.RiskRemoved != 120 {
		t.Errorf("PyYAML action = %+v, want both Findings and risk 120", py)
	}
	if !slices.Contains(py.InstalledVersions, "9.9") {
		t.Errorf("InstalledVersions = %v, want the later build's 9.9 carried across the merge", py.InstalledVersions)
	}
}

// EDR-CORRELATION-01 D6 — a plan names only the packages that CARRY the flaw.
//
// The case this exists for, observed live: CVE-2019-10086 is Apache Commons BeanUtils, and
// `javapackages-filesystem` was rebuilt beside it in one module stream. Asked about the CVE and
// handed that component, the model wrote that it "affects the Java packages filesystem component"
// at confidence 0.95 — and Grounding Verification PASSED it, because the projection said so.
//
// The Finding is not lost: it appears under the package that does carry it. Only the bystander is
// dropped from the ACTION, because "upgrade javapackages-filesystem" is not a task anyone can
// carry out to fix a BeanUtils flaw.
func TestPlanActions_NamesOnlyCarriers(t *testing.T) {
	carrier := domain.PostureComponent{
		PURL: "pkg:rpm/rocky/apache-commons-beanutils@1.9.3", Name: "apache-commons-beanutils",
		Source: "apache-commons-beanutils", Version: "1.9.3", Ecosystem: "rpm", ClaimClass: "carrier",
	}
	bystander := domain.PostureComponent{
		PURL: "pkg:rpm/rocky/javapackages-filesystem@5.3.0", Name: "javapackages-filesystem",
		Source: "javapackages-filesystem", Version: "5.3.0", Ecosystem: "rpm", ClaimClass: "scope",
	}
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-2019-10086", ResidualPriority: 76,
			Components: []domain.PostureComponent{carrier, bystander}},
	}}
	got := p.PlanActions()
	if len(got) != 1 {
		t.Fatalf("actions = %d, want 1 — only the carrier is actionable: %+v", len(got), got)
	}
	if got[0].Package != "apache-commons-beanutils" {
		t.Errorf("action names %q, want the carrier", got[0].Package)
	}
	// The Finding is still closed by that action — nothing was dropped from the plan's coverage.
	if len(got[0].FindingIDs) != 1 || got[0].RiskRemoved != 76 {
		t.Errorf("action = %+v, want the Finding still counted once at 76", got[0])
	}
}

// Unknown attribution behaves exactly as before this change: a card NVD has not enriched yields
// components with no class, and every one of them stays actionable.
func TestPlanActions_UnknownAttributionKeepsEveryComponent(t *testing.T) {
	// Distinct CVEs, so mergeSiblings does not fold them for the unrelated reason that they close
	// the identical CVE set — this test is about attribution, not merging.
	p := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 50, Components: []domain.PostureComponent{
			{Name: "a", Source: "a", Ecosystem: "rpm"}, // no ClaimClass at all
		}},
		{FindingID: "f2", CVE: "CVE-2", ResidualPriority: 40, Components: []domain.PostureComponent{
			{Name: "b", Source: "b", Ecosystem: "rpm"},
		}},
	}}
	if got := p.PlanActions(); len(got) != 2 {
		t.Errorf("actions = %d, want 2 — unknown must not drop anything: %+v", len(got), got)
	}
}
