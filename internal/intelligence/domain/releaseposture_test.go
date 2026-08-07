package domain_test

import (
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
