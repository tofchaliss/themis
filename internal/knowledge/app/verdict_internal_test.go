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
