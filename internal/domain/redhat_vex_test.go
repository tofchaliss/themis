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

func TestRedHatMainStreamMajor(t *testing.T) {
	tests := map[string]string{
		"cpe:/o:redhat:enterprise_linux:8":      "8",
		"cpe:/a:redhat:enterprise_linux:9":      "9",
		"cpe:/o:redhat:enterprise_linux:10":     "10",
		"cpe:/a:redhat:enterprise_linux:10.1":   "10",
		"cpe:/a:redhat:enterprise_linux:8::crb": "8", // CodeReady Builder is still main-stream 8
		// Minor-version-locked backport streams are NOT the main stream → excluded.
		"cpe:/a:redhat:rhel_e4s:9.0":              "",
		"cpe:/a:redhat:rhel_eus:8.6":              "",
		"cpe:/a:redhat:rhel_aus:8.4":              "",
		"cpe:/a:redhat:rhel_tus:8.8":              "",
		"cpe:/o:redhat:enterprise_linux_eus:10.0": "",
		"cpe:/o:redhat:openshift:4.14":            "", // not an EL stream
		"":                                        "",
	}
	for in, want := range tests {
		if got := redHatMainStreamMajor(in); got != want {
			t.Errorf("redHatMainStreamMajor(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVerdictForStreamIgnoresMinorLockedBackports reproduces the libtiff
// CVE-2026-4775 false-resolution: Red Hat ships the el8 main-stream fix at
// release 37 (el8_10) but also older AUS/TUS/E4S backports (el8_6.2 release 21,
// el8_8.2 release 29) listed AFTER it. The verdict must resolve to the main-stream
// 37 fix, never the el8_8.2 backport — otherwise an el8_10 install at release 36
// (36 > 29) is falsely "fixed".
func TestVerdictForStreamIgnoresMinorLockedBackports(t *testing.T) {
	report := RedHatCVEReport{
		AffectedReleases: []RedHatAffectedRelease{
			{PackageNEVRA: "libtiff-0:4.0.9-37.el8_10", CPE: "cpe:/a:redhat:enterprise_linux:8", Advisory: "RHSA-2026:16055"},
			{PackageNEVRA: "libtiff-0:4.0.9-21.el8_6.2", CPE: "cpe:/a:redhat:rhel_aus:8.6", Advisory: "RHSA-2026:19657"},
			{PackageNEVRA: "libtiff-0:4.0.9-29.el8_8.2", CPE: "cpe:/a:redhat:rhel_e4s:8.8", Advisory: "RHSA-2026:19604"},
		},
	}
	v := report.VerdictForStream("libtiff", "8")
	if !v.Covered || v.FixedEVR != "0:4.0.9-37.el8_10" || v.Advisory != "RHSA-2026:16055" {
		t.Fatalf("must resolve the main-stream el8_10 fix, got %+v", v)
	}
}

// TestVerdictForStreamPicksMaxMainStreamFix verifies that when Red Hat ships more
// than one main-stream fix (different z-streams, e.g. el9_7.3 then el9_8), the
// verdict keeps the highest EVR so an install must clear every published fix.
func TestVerdictForStreamPicksMaxMainStreamFix(t *testing.T) {
	report := RedHatCVEReport{
		AffectedReleases: []RedHatAffectedRelease{
			{PackageNEVRA: "libtiff-0:4.4.0-15.el9_7.3", CPE: "cpe:/a:redhat:enterprise_linux:9", Advisory: "RHSA-2026:12271"},
			{PackageNEVRA: "libtiff-0:4.4.0-18.el9_8", CPE: "cpe:/a:redhat:enterprise_linux:9", Advisory: "RHSA-2026:19363"},
		},
	}
	v := report.VerdictForStream("libtiff", "9")
	if v.FixedEVR != "0:4.4.0-18.el9_8" || v.Advisory != "RHSA-2026:19363" {
		t.Fatalf("must keep the highest main-stream fix, got %+v", v)
	}
	// Re-ordering the entries must not change the result (order-independent max).
	report.AffectedReleases[0], report.AffectedReleases[1] = report.AffectedReleases[1], report.AffectedReleases[0]
	if v := report.VerdictForStream("libtiff", "9"); v.FixedEVR != "0:4.4.0-18.el9_8" {
		t.Fatalf("max must be order-independent, got %+v", v)
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
