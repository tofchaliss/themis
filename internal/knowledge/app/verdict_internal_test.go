package app

import (
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The fixtures are the measured KN-VERDICT-1 estate (CVE-2025-47273 / MRF, 2026-09-02):
// a card holding the Red Hat bound attributed to the SOURCE package, an rpm owner at the
// patched build, and its pypi .egg-info shadow reporting the bare upstream version.
var (
	cardView = domain.EnterpriseView{Fixes: []domain.FixedVersion{
		{Package: "python-setuptools", Version: "0:39.2.0-9.el8_10", Ecosystem: "rpm"},
		{Package: "setuptools", Version: "78.1.1", Ecosystem: "pypi"},
	}}
	patchedRPM = InventoryComponent{
		PURL: "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10", Name: "platform-python-setuptools",
		Version: "39.2.0-9.el8_10", Ecosystem: "rpm", Source: "python-setuptools",
	}
	unpatchedRPM = InventoryComponent{
		PURL: "pkg:rpm/rhel/platform-python-setuptools@39.2.0-8.el8", Name: "platform-python-setuptools",
		Version: "39.2.0-8.el8", Ecosystem: "rpm", Source: "python-setuptools",
	}
	pypiShadow = InventoryComponent{
		PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi",
	}
	pipCopy = InventoryComponent{
		PURL: "pkg:pypi/setuptools@70.3.0", Name: "setuptools", Version: "70.3.0", Ecosystem: "pypi",
	}
)

// The Observed hop: an explicit SBOM ownership edge routes the verdict through the owning
// rpm's own build — and only an owner that actually carries the fix clears anything.
func TestBridgeObserved(t *testing.T) {
	owners := map[string]string{pypiShadow.PURL: patchedRPM.PURL}

	v := judgeOccurrence(cardView, pypiShadow, BridgeContext{
		Siblings: []InventoryComponent{patchedRPM}, Owners: owners, InferredBridge: false,
	})
	if v.State != domain.VerdictClearedVendorFix || v.Grade != domain.VerdictGradeObserved {
		t.Fatalf("edge to patched owner: verdict = %+v, want an observed clearance", v)
	}
	if !strings.Contains(v.Reason, "SBOM ownership") || !strings.Contains(v.Reason, "platform-python-setuptools") {
		t.Errorf("reason must name the owner and the evidence kind, got %q", v.Reason)
	}

	// Owner BELOW the bound: the machine genuinely is vulnerable — the edge must not clear.
	v = judgeOccurrence(cardView, pypiShadow, BridgeContext{
		Siblings: []InventoryComponent{unpatchedRPM},
		Owners:   map[string]string{pypiShadow.PURL: unpatchedRPM.PURL},
	})
	if !v.State.IsOpen() {
		t.Errorf("edge to UNPATCHED owner cleared: %+v — the bridge routed the verdict but the verdict must still fail", v)
	}

	// An edge whose owner is not on record, or not rpm-class, proves nothing.
	v = judgeOccurrence(cardView, pypiShadow, BridgeContext{Owners: owners})
	if !v.State.IsOpen() {
		t.Errorf("edge with no owner in the sibling set cleared: %+v", v)
	}
	v = judgeOccurrence(cardView, pypiShadow, BridgeContext{
		Siblings: []InventoryComponent{{PURL: patchedRPM.PURL, Name: "x", Version: "1", Ecosystem: "npm"}},
		Owners:   owners,
	})
	if !v.State.IsOpen() {
		t.Errorf("non-rpm owner cleared: %+v", v)
	}
}

// The Inferred hop is the measured MRF case: no ownership edge, but the same inventory holds
// the patched rpm whose fix-attribution key normalizes to the language row's name and whose
// upstream version equals it exactly. Cleared — labeled as Themis's own match.
func TestBridgeInferred_TheMeasuredCase(t *testing.T) {
	bridge := BridgeContext{Siblings: []InventoryComponent{patchedRPM, pipCopy}, InferredBridge: true}

	v := judgeOccurrence(cardView, pypiShadow, bridge)
	if v.State != domain.VerdictClearedVendorFix || v.Grade != domain.VerdictGradeInferred {
		t.Fatalf("MRF shape: verdict = %+v, want an INFERRED clearance", v)
	}
	if !strings.Contains(v.Reason, "inferred") || !strings.Contains(v.Reason, "0:39.2.0-9.el8_10") {
		t.Errorf("reason must be labeled inferred and name the bound, got %q", v.Reason)
	}

	// THE binding validation bound: the pip-installed 70.3.0 copy is BELOW the upstream fix
	// and no distro backport covers it — it must stay open however the bridge is armed.
	v = judgeOccurrence(cardView, pipCopy, bridge)
	if !v.State.IsOpen() {
		t.Fatalf("the pip copy (70.3.0) was cleared: %+v — the fix was validated against the wrong outcome", v)
	}

	// Strict mode (D4 switch off): the same shape stays open.
	v = judgeOccurrence(cardView, pypiShadow, BridgeContext{Siblings: []InventoryComponent{patchedRPM}})
	if !v.State.IsOpen() {
		t.Errorf("strict mode cleared without an edge: %+v", v)
	}
}

// The accepted, documented limit of the guess grade (EDR-VERDICT-01 honest limits): a
// hand-installed pip copy of the EXACT distro version is indistinguishable from the rpm's
// shadow by name+version alone, and WOULD be cleared. This test pins the limit so a future
// change that silently widens or narrows it fails loudly.
func TestBridgeInferred_ExactDistroVersionPipCopyIsTheKnownLimit(t *testing.T) {
	handInstalled := InventoryComponent{
		PURL: "pkg:pypi/setuptools@39.2.0?vcs_url=local", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi",
	}
	v := judgeOccurrence(cardView, handInstalled, BridgeContext{
		Siblings: []InventoryComponent{patchedRPM}, InferredBridge: true,
	})
	if v.State != domain.VerdictClearedVendorFix || v.Grade != domain.VerdictGradeInferred {
		t.Errorf("the documented limit changed: %+v — update EDR-VERDICT-01's honest limits if this is intentional", v)
	}
}

// The name-affinity guard: version equality alone must never clear a stranger. python3-ply
// sits at upstream 3.9 on the same module-stream card — a pypi row named differently at 3.9
// stays open.
func TestBridgeInferred_Guards(t *testing.T) {
	ply := InventoryComponent{
		PURL: "pkg:rpm/rhel/python3-ply@3.9-9.el8", Name: "python3-ply",
		Version: "3.9-9.el8", Ecosystem: "rpm", Source: "python-ply",
	}
	plyCard := domain.EnterpriseView{Fixes: []domain.FixedVersion{
		{Package: "python-ply", Version: "0:3.9-10.el8", Ecosystem: "rpm"},
	}}
	stranger := InventoryComponent{PURL: "pkg:pypi/foo@3.9", Name: "foo", Version: "3.9", Ecosystem: "pypi"}
	// ply's own build is below its fix here, so first make it at/above to isolate the name guard.
	plyPatched := ply
	plyPatched.Version = "3.9-10.el8"
	if v := judgeOccurrence(plyCard, stranger, BridgeContext{Siblings: []InventoryComponent{plyPatched}, InferredBridge: true}); !v.State.IsOpen() {
		t.Errorf("version-only affinity cleared a stranger: %+v", v)
	}
	// And the guard passes when the SIBLING's bare name (not its source) is the affine one.
	pyyaml := InventoryComponent{
		PURL: "pkg:rpm/rhel/python3-pyyaml@5.4.1-1.el8", Name: "python3-pyyaml",
		Version: "5.4.1-1.el8", Ecosystem: "rpm", Source: "PyYAML",
	}
	yamlCard := domain.EnterpriseView{Fixes: []domain.FixedVersion{
		{Package: "PyYAML", Version: "0:5.4.1-1.el8", Ecosystem: "rpm"},
	}}
	shadow := InventoryComponent{PURL: "pkg:pypi/pyyaml@5.4.1", Name: "pyyaml", Version: "5.4.1", Ecosystem: "pypi"}
	if v := judgeOccurrence(yamlCard, shadow, BridgeContext{Siblings: []InventoryComponent{pyyaml}, InferredBridge: true}); v.State.IsOpen() {
		t.Errorf("name-affine sibling (via bare name) did not clear: %+v", v)
	}

	// Non-candidates never reach the guess: rpm/apk-class rows, deb rows, blank versions/names,
	// the row itself, and non-rpm siblings.
	bridge := BridgeContext{Siblings: []InventoryComponent{patchedRPM, pypiShadow}, InferredBridge: true}
	for name, comp := range map[string]InventoryComponent{
		"rpm-class":     {PURL: "pkg:rpm/x@1", Name: "setuptools", Version: "39.2.0", Ecosystem: "rpm"},
		"deb-class":     {PURL: "pkg:deb/x@1", Name: "setuptools", Version: "39.2.0", Ecosystem: "deb"},
		"blank-version": {PURL: "pkg:pypi/setuptools", Name: "setuptools", Ecosystem: "pypi"},
		"blank-name":    {PURL: "pkg:pypi/x@39.2.0", Version: "39.2.0", Ecosystem: "pypi"},
	} {
		if v := judgeOccurrence(domain.EnterpriseView{Fixes: cardView.Fixes}, comp, bridge); v.State != domain.VerdictOpen && name != "rpm-class" {
			t.Errorf("%s reached a clearance: %+v", name, v)
		}
	}
	// A pypi sibling (the row's own shadow twin) is not a bridge candidate.
	if v := judgeOccurrence(cardView, pypiShadow, BridgeContext{Siblings: []InventoryComponent{pipCopy}, InferredBridge: true}); !v.State.IsOpen() {
		t.Errorf("a non-rpm sibling bridged: %+v", v)
	}
}

func TestRPMUpstreamVersion(t *testing.T) {
	for in, want := range map[string]string{
		"0:39.2.0-9.el8_10":                  "39.2.0",
		"39.2.0-9.el8_10":                    "39.2.0",
		"platform-python-setuptools-39.2.0-9.el8_10.noarch": "39.2.0",
		"3.9-9.el8": "3.9",
		"1.0.2k":    "1.0.2k",
		"":          "",
	} {
		if got := rpmUpstreamVersion(in); got != want {
			t.Errorf("rpmUpstreamVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// D10 / KN-OPEN-REASON-1 (2026-10-26): an open rpm verdict states its premise. The fixtures are
// the measured fully-patched RHEL 8 host: mysql 8.0 and ruby 2.5 module streams whose el8 fixes
// are all 8.4 / 3.x module builds.
func TestOpenReason_Shapes(t *testing.T) {
	view := domain.EnterpriseView{Fixes: []domain.FixedVersion{
		{Package: "mysql-libs", Version: "0:8.4.11-1.module+el8.10.0+24662+2d989aa9", Ecosystem: "rpm"},
		{Package: "mysql-libs", Version: "0:8.4.11-1.module+el9.8.0+24663+27effc5a", Ecosystem: "rpm"},
		{Package: "ruby-libs", Version: "0:3.1.5-6.module+el8.10.0+24567+c4e5368e", Ecosystem: "rpm"},
		{Package: "ruby-libs", Version: "0:3.3.12-8.module+el8.10.0+24568+2bbebe96", Ecosystem: "rpm"},
		{Package: "httpd", Version: "0:2.4.37-65.module+el8.10.0+40257+286895ef.9", Ecosystem: "rpm"},
		{Package: "perl-File-Path", Version: "0:2.16-439.module+el8.10.0+1616+0d20cc68", Ecosystem: "rpm"},
		{Package: "perl-File-Path", Version: "0:2.16-439.module+el8.10.0+21354+3ad137bb", Ecosystem: "rpm"},
		{Package: "openssl", Version: "1:1.1.1k-14.el8_6", Ecosystem: "rpm"},
		{Package: "kernel", Version: "0:5.14.0-570.el9_6", Ecosystem: "rpm"},
	}}
	rpm := func(name, version string) InventoryComponent {
		return InventoryComponent{PURL: "pkg:rpm/redhat/" + name + "@" + version, Name: name, Version: version, Ecosystem: "rpm"}
	}
	cases := []struct {
		name string
		comp InventoryComponent
		want []string // every substring the reason must carry
		not  []string // substrings it must not
	}{
		{"another module stream, one series", rpm("mysql-libs", "8.0.46-1.module+el8.10.0+24370+d5a391f0"),
			[]string{"below every el8 fix for mysql-libs", "0:8.4.11-1.module+el8.10.0", "another series (8.4, installed 8.0)", "likely another module stream"},
			[]string{"el9.8.0"}},
		{"another module stream, two series", rpm("ruby-libs", "2.5.9-116.module+el8.10.0+24853+52b5af56"),
			[]string{"below every el8 fix for ruby-libs", "another series (3.1, 3.3, installed 2.5)"}, nil},
		{"base-repo install, module-only fixes", rpm("perl-File-Path", "2.15-2.el8"),
			[]string{"below every el8 fix for perl-File-Path", "installed package is not (base repository)", "published only for a module stream"}, []string{"another series"}},
		{"same stream, simply behind", rpm("httpd", "2.4.37-30.module+el8.3.0+1234+abcd"),
			[]string{"installed 2.4.37-30.module+el8.3.0+1234+abcd is below every el8 fix for httpd"}, []string{"another series"}},
		{"plain build behind a plain fix", rpm("openssl", "1:1.1.1k-12.el8_5"),
			[]string{"below every el8 fix for openssl: 1:1.1.1k-14.el8_6"}, []string{"module"}},
		{"fixes only for other majors", rpm("kernel", "4.18.0-553.el8_10"),
			[]string{"no el8 fix on record for kernel", "1 fix bound(s) known for other EL streams"}, nil},
		{"no fix at all", rpm("curl", "7.61.1-34.el8"), []string{"no vendor fix on record for curl"}, nil},
		{"no EL marker on the install", rpm("openssl", "1.1.1k-12"), []string{"names no EL stream"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := judgeOccurrence(view, c.comp, BridgeContext{})
			if !v.State.IsOpen() {
				t.Fatalf("state = %q, want open", v.State)
			}
			for _, w := range c.want {
				if !strings.Contains(v.Reason, w) {
					t.Errorf("reason %q must contain %q", v.Reason, w)
				}
			}
			for _, n := range c.not {
				if strings.Contains(v.Reason, n) {
					t.Errorf("reason %q must not contain %q", v.Reason, n)
				}
			}
		})
	}
}

// Only the rpm world gets a premise; a cleared row keeps its own; a language row stays as
// before — "open" there already means exactly "not cleared".
func TestOpenReason_ScopeAndClearance(t *testing.T) {
	if v := judgeOccurrence(cardView, pypiShadow, BridgeContext{}); v.Reason != "" || !v.State.IsOpen() {
		t.Errorf("a non-rpm open row carries no premise, got %q / %q", v.State, v.Reason)
	}
	if v := judgeOccurrence(cardView, patchedRPM, BridgeContext{}); v.State.IsOpen() || !strings.Contains(v.Reason, "vendor fix") {
		t.Errorf("a cleared row keeps its clearance premise, got %q / %q", v.State, v.Reason)
	}
	if v := judgeOccurrence(cardView, unpatchedRPM, BridgeContext{}); !v.State.IsOpen() || !strings.Contains(v.Reason, "below every el8 fix for python-setuptools") {
		t.Errorf("an open rpm row says what it was compared against, got %q / %q", v.State, v.Reason)
	}
}

func TestListBoundsAndJoinReasons(t *testing.T) {
	if got := listBounds([]string{"a", "b", "c", "d", "e"}); got != "a, b, c (+2 more)" {
		t.Errorf("listBounds = %q", got)
	}
	if got := listBounds([]string{"a"}); got != "a" {
		t.Errorf("listBounds one = %q", got)
	}
	for _, c := range [][3]string{{"", "p", "p"}, {"f", "", "f"}, {"f", "p", "f; p"}, {"", "", ""}} {
		if got := joinReasons(c[0], c[1]); got != c[2] {
			t.Errorf("joinReasons(%q,%q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	if s := upstreamSeries("15-1.module+el8.6.0+1+a"); s != "15" {
		t.Errorf("single-segment series = %q", s)
	}
	// A plain build on either side, or a fix in the install's own series, is "simply behind".
	if otherStreamSeries("8.0.46-1.module+el8.10.0+1+a", []string{"0:8.4.11-1.el8"}) != nil {
		t.Error("a plain fix must not read as another stream")
	}
	if otherStreamSeries("8.0.46-1.module+el8.10.0+1+a", []string{"0:8.4.11-1.module+el8.10.0+2+b", "0:8.0.50-1.module+el8.10.0+3+c"}) != nil {
		t.Error("a fix in the install's own series means the install is behind, not on another stream")
	}
	// A build whose upstream segment cannot be read (nothing before the first hyphen) names no
	// series on either side, so no stream claim is made.
	if otherStreamSeries("-1.module+el8.10.0+1+a", []string{"0:8.4.11-1.module+el8.10.0+2+b"}) != nil {
		t.Error("an unreadable installed series must not read as another stream")
	}
	if otherStreamSeries("8.0.46-1.module+el8.10.0+1+a", []string{"-1.module+el8.10.0+2+b"}) != nil {
		t.Error("an unreadable fix series must not read as another stream")
	}
}

// KN-EPOCH-1 (2026-10-27): the Nessus inventory keeps the epoch on the purl only. The verdict
// must compare the install WITH it, or a fully patched epoch-1 package reads as behind forever.
func TestJudgeOccurrence_EpochRestoredFromPURL(t *testing.T) {
	view := domain.EnterpriseView{Fixes: []domain.FixedVersion{
		{Package: "java-21-openjdk", Version: "1:21.0.12.1.1-1.1.el8", Ecosystem: "rpm"},
	}}
	nessus := InventoryComponent{
		PURL:    "pkg:rpm/redhat/java-21-openjdk@21.0.12.1.1-1.1.el8?distro=rhel-8.10&epoch=1",
		Name:    "java-21-openjdk", Version: "21.0.12.1.1-1.1.el8", Ecosystem: "rpm",
	}
	v := judgeOccurrence(view, nessus, BridgeContext{})
	if v.State.IsOpen() || !strings.Contains(v.Reason, "installed 1:21.0.12.1.1-1.1.el8") {
		t.Errorf("the same build must clear, and the premise must show the epoch it was compared with; got %q / %q", v.State, v.Reason)
	}
	// Without the qualifier nothing is invented: the row stays open and says so.
	bare := nessus
	bare.PURL = "pkg:rpm/redhat/java-21-openjdk@21.0.12.1.1-1.1.el8?distro=rhel-8.10"
	if v := judgeOccurrence(view, bare, BridgeContext{}); !v.State.IsOpen() || !strings.Contains(v.Reason, "installed 21.0.12.1.1-1.1.el8 is below") {
		t.Errorf("no epoch anywhere: open, compared as written; got %q / %q", v.State, v.Reason)
	}
	// The bridge hops read their rpm the same way.
	owner := InventoryComponent{PURL: "pkg:rpm/redhat/java-21-openjdk-headless@21.0.12.1.1-1.1.el8?epoch=1",
		Name: "java-21-openjdk-headless", Version: "21.0.12.1.1-1.1.el8", Ecosystem: "rpm", Source: "java-21-openjdk"}
	shadow := InventoryComponent{PURL: "pkg:maven/openjdk@21.0.12", Name: "openjdk", Version: "21.0.12", Ecosystem: "maven"}
	v = judgeOccurrence(view, shadow, BridgeContext{Siblings: []InventoryComponent{owner}, Owners: map[string]string{shadow.PURL: owner.PURL}})
	if v.State.IsOpen() || v.Grade != domain.VerdictGradeObserved {
		t.Errorf("observed hop through an epoch-on-purl owner must clear; got %q / %q / %q", v.State, v.Grade, v.Reason)
	}
}
