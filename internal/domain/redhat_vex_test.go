package domain

import "testing"

// ncursesReport mirrors the real Red Hat Security Data API response for
// CVE-2022-29458: Low severity, RHEL-8 "Not affected" (the vuln is build-time
// tic, back-ported away from libncurses), fixed only on RHEL-9.
var ncursesReport = RedHatCVEReport{
	CVEID:          "CVE-2022-29458",
	ThreatSeverity: "Low",
	CVSS3:          "6.1",
	Statement:      "vulnerable code is the build-time tic",
	PackageStates: []RedHatPackageState{
		{PackageName: "ncurses", FixState: "Not affected", CPE: "cpe:/o:redhat:enterprise_linux:7"},
		{PackageName: "ncurses", FixState: "Not affected", CPE: "cpe:/o:redhat:enterprise_linux:8"},
	},
	AffectedReleases: []RedHatAffectedRelease{
		{PackageNEVRA: "ncurses-0:6.2-10.20210508.el9_6.2", CPE: "cpe:/o:redhat:enterprise_linux:9", Advisory: "RHSA-2025:12876"},
	},
}

func TestVerdictForStreamNotAffected(t *testing.T) {
	v := ncursesReport.VerdictForStream("ncurses", "8")
	if !v.Covered || !v.NotAffected {
		t.Fatalf("el8 ncurses must be covered+not_affected: %+v", v)
	}
	if v.FixedEVR != "" {
		t.Fatalf("el8 has no fix NEVRA: %+v", v)
	}
}

func TestVerdictForStreamFixed(t *testing.T) {
	v := ncursesReport.VerdictForStream("ncurses", "9")
	if !v.Covered || v.NotAffected {
		t.Fatalf("el9 ncurses is affected+fixed, not not_affected: %+v", v)
	}
	if v.FixedEVR != "0:6.2-10.20210508.el9_6.2" || v.Advisory != "RHSA-2025:12876" {
		t.Fatalf("el9 fix NEVRA/advisory = %+v", v)
	}
}

func TestVerdictForStreamUncovered(t *testing.T) {
	// el10 — Red Hat published nothing for this stream.
	if v := ncursesReport.VerdictForStream("ncurses", "10"); v.Covered {
		t.Fatalf("el10 must be uncovered: %+v", v)
	}
	// Different package on a covered stream — no verdict.
	if v := ncursesReport.VerdictForStream("openssl", "8"); v.Covered {
		t.Fatalf("openssl must not pick up ncurses verdict: %+v", v)
	}
	// Empty inputs.
	if v := ncursesReport.VerdictForStream("", "8"); v.Covered {
		t.Fatalf("empty package must be uncovered: %+v", v)
	}
	if v := ncursesReport.VerdictForStream("ncurses", ""); v.Covered {
		t.Fatalf("empty stream must be uncovered: %+v", v)
	}
}

func TestVerdictForStreamAffectedState(t *testing.T) {
	report := RedHatCVEReport{
		PackageStates: []RedHatPackageState{
			{PackageName: "openssl", FixState: "Will not fix", CPE: "cpe:/o:redhat:enterprise_linux:8"},
		},
	}
	v := report.VerdictForStream("openssl", "8")
	if !v.Covered || v.NotAffected || v.FixState != "Will not fix" {
		t.Fatalf("will-not-fix verdict = %+v", v)
	}
}

func TestVerdictForStreamHyphenatedPackage(t *testing.T) {
	// Package names contain hyphens; the NEVRA name prefix must match exactly.
	report := RedHatCVEReport{
		AffectedReleases: []RedHatAffectedRelease{
			{PackageNEVRA: "perl-Time-Local-1:1.300-4.module+el8.10.0+40155+64ce2d41", CPE: "cpe:/o:redhat:enterprise_linux:8"},
		},
	}
	v := report.VerdictForStream("perl-Time-Local", "8")
	if !v.Covered || v.FixedEVR != "1:1.300-4.module+el8.10.0+40155+64ce2d41" {
		t.Fatalf("hyphenated NEVRA EVR = %+v", v)
	}
	// A shorter package name must NOT match a longer NEVRA name (perl ≠ perl-Time-Local).
	if v := report.VerdictForStream("perl", "8"); v.Covered {
		t.Fatalf("perl must not match perl-Time-Local NEVRA: %+v", v)
	}
}

func TestRedHatCPEMajor(t *testing.T) {
	tests := map[string]string{
		"cpe:/o:redhat:enterprise_linux:8":  "8",
		"cpe:/a:redhat:enterprise_linux:9":  "9",
		"cpe:/a:redhat:rhel_e4s:9.0":        "9",
		"cpe:/a:redhat:rhel_eus:8.6":        "8",
		"cpe:/o:redhat:enterprise_linux:10": "10",
		"cpe:/o:redhat:openshift:4.14":      "", // not an EL stream
		"":                                  "",
	}
	for in, want := range tests {
		if got := redHatCPEMajor(in); got != want {
			t.Errorf("redHatCPEMajor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedHatNEVRAEVR(t *testing.T) {
	evr, ok := redHatNEVRAEVR("ncurses-0:6.2-10.20210508.el9_6.2", "ncurses")
	if !ok || evr != "0:6.2-10.20210508.el9_6.2" {
		t.Fatalf("ncurses EVR = %q ok=%v", evr, ok)
	}
	if _, ok := redHatNEVRAEVR("ncurses-libs-0:6.2-1.el8", "ncurses"); ok {
		t.Fatal("ncurses must not match ncurses-libs NEVRA")
	}
	if _, ok := redHatNEVRAEVR("ncurses", "ncurses"); ok {
		t.Fatal("a bare name with no EVR must not match")
	}
}
