package value

import "testing"

func TestNormalizeEcosystem(t *testing.T) {
	cases := map[string]string{
		"golang":   "go",
		"Golang":   "go",
		"python":   "pypi",
		" PyThon ": "pypi",
		"npm":      "npm",
		" NPM ":    "npm",
		"":         "",
	}
	for in, want := range cases {
		if got := NormalizeEcosystem(in); got != want {
			t.Errorf("NormalizeEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyEcosystem(t *testing.T) {
	cases := map[string]VersionClass{
		"apk":            VersionClassAPK,
		"Alpine":         VersionClassAPK,
		"wolfi":          VersionClassAPK,
		"chainguard":     VersionClassAPK,
		"Alpine Linux 3": VersionClassAPK, // contains-match, not exact
		"cgr.wolfi.dev":  VersionClassAPK, // contains-match
		"rpm":            VersionClassRPM,
		"redhat":         VersionClassRPM,
		"rhel":           VersionClassRPM,
		"rocky":          VersionClassRPM,
		"rocky linux":    VersionClassRPM,
		"Rocky Linux 9":  VersionClassRPM, // contains-match
		"almalinux":      VersionClassRPM,
		"AlmaLinux:9":    VersionClassRPM, // contains-match
		"centos":         VersionClassRPM,
		"Red Hat 8":      VersionClassRPM, // contains "red hat"
		"fedora":         VersionClassRPM,
		"npm":            VersionClassGeneric,
		"PyPI":           VersionClassGeneric,
		"go":             VersionClassGeneric,
		"":               VersionClassGeneric,
	}
	for in, want := range cases {
		if got := ClassifyEcosystem(in); got != want {
			t.Errorf("ClassifyEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersionsGeneric(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.10", "1.9", 1},   // multi-digit numeric, not lexical
		{"1.9", "1.10", -1},  // mirror
		{"1.01", "1.1", 0},   // leading zeros ignored
		{"1.0", "1.0.1", -1}, // shorter is older
		{"1.0.1", "1.0", 1},  // mirror
		{"1.a", "1.0", -1},   // numeric outranks alpha at same position
		{"1.0", "1.a", 1},    // mirror
		{"1.0a", "1.0b", -1}, // letter runs compare lexically
		{"1.0-rc", "1.0-rd", -1},
		{"1-", "1.2", -1}, // left empties to separators mid-loop (inner break, left side)
		{"1.2", "1-", 1},  // right empties to separators mid-loop (inner break, right side)
	}
	for _, c := range cases {
		if got := CompareVersions("", c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareVersionsAPK(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.36.1-r0", "1.36.1-r0", 0},
		{"1.36.1-r0", "1.36.1-r1", -1}, // revision suffix orders
		{"1.36.1-r0", "1.36.1", 1},     // extra revision segment is newer
		{"1.2", "1.10", -1},            // numeric segments compare numerically
		{"1.10", "1.2", 1},             // mirror
		{"1.2.3", "1.2.3", 0},
		{"1.01", "1.1", 0}, // equal ints, different strings → numeric-equal segment branch
	}
	for _, c := range cases {
		if got := CompareVersions("apk", c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(apk,%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareVersionsRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1:1.0", "2.0", 1},    // epoch dominates
		{"2.0", "1:1.0", -1},   // mirror
		{"1.0~rc1", "1.0", -1}, // tilde pre-release sorts before release
		{"1.0", "1.0~rc1", 1},  // mirror
		{"1.0-1", "1.0-2", -1}, // release compared
		{"1.0", "1.a", 1},      // numeric outranks alpha (bStart==j, numeric)
		{"1.a", "1.0", -1},     // mirror (bStart==j, alpha)
		{"a:1.0", "a:1.0", 0},  // non-integer epoch prefix → treated as version 0
		{"1.0~a", "1.0~b", -1}, // both tilde, then alpha compare
		{"1.0", "1.0.5", -1},   // shorter run exhausts first (rpmvercmp break, left)
		{"1.0.5", "1.0", 1},    // mirror (rpmvercmp break, right)
		{"1.10", "1.9", 1},     // multi-digit numeric segment (longer run wins)
		{"1.9", "1.10", -1},    // mirror (shorter run loses)
		{"1.2", "1_2", 0},      // differ only by separator → exhausts both, equal
	}
	for _, c := range cases {
		if got := CompareVersions("rpm", c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(rpm,%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAffectedRangeMatches(t *testing.T) {
	cases := []struct {
		name    string
		r       AffectedRange
		version string
		want    bool
	}{
		{"empty groups match all", AffectedRange{Groups: nil}, "9.9", true},
		{"wildcard matches all", AffectedRange{Groups: []string{"*"}}, "9.9", true},
		{"unknown matches all", AffectedRange{Groups: []string{"unknown"}}, "9.9", true},
		{"none matches nothing", AffectedRange{Groups: []string{"none"}}, "1.0", false},
		{"exact match", AffectedRange{Groups: []string{"2.0"}}, "2.0", true},
		{"exact non-match falls to default", AffectedRange{Groups: []string{"2.0"}}, "3.0", false},
		{"in half-open interval", AffectedRange{Groups: []string{">= 1.0, < 3.0"}}, "2.0", true},
		{"below lower bound", AffectedRange{Groups: []string{">= 1.0, < 3.0"}}, "0.9", false},
		{"at upper exclusive bound", AffectedRange{Groups: []string{">= 1.0, < 3.0"}}, "3.0", false},
		{"OR across groups", AffectedRange{Groups: []string{"< 1.0", ">= 5.0"}}, "6.0", true},
		{"inclusive upper", AffectedRange{Groups: []string{"<= 2.0"}}, "2.0", true},
		{"exclusive lower", AffectedRange{Groups: []string{"> 1.0"}}, "1.0", false},
		{"empty tokens in group are skipped", AffectedRange{Groups: []string{" , >= 1.0"}}, "2.0", true},
		{"all-empty group does not match", AffectedRange{Groups: []string{" , "}}, "2.0", false},
	}
	for _, c := range cases {
		if got := c.r.Matches(c.version); got != c.want {
			t.Errorf("%s: Matches(%q) = %v, want %v", c.name, c.version, got, c.want)
		}
	}
}

func TestApplicability(t *testing.T) {
	inRange := AffectedRange{Ecosystem: "", Groups: []string{">= 1.0, < 3.0"}}
	cases := []struct {
		name    string
		r       AffectedRange
		version string
		want    RangeVerdict
	}{
		{"in range", inRange, "2.0", RangeInRange},
		{"out of range", inRange, "5.0", RangeOutOfRange},
		{"qualifiers stripped before compare", inRange, "2.0?arch=x86_64", RangeInRange},
		{"empty version → undecidable", inRange, "  ", RangeUndecidable},
		{"empty range → undecidable", AffectedRange{Groups: nil}, "2.0", RangeUndecidable},
		{"all-none range → undecidable", AffectedRange{Groups: []string{"none"}}, "2.0", RangeUndecidable},
		{"wildcard → in range", AffectedRange{Groups: []string{"*"}}, "2.0", RangeInRange},
		{"apk revision out of range", AffectedRange{Ecosystem: "apk", Groups: []string{"< 1.36.1-r5"}}, "1.36.1-r9", RangeOutOfRange},
	}
	for _, c := range cases {
		if got := c.r.Applicability(c.version); got != c.want {
			t.Errorf("%s: Applicability(%q) = %v, want %v", c.name, c.version, got, c.want)
		}
	}
}

func TestRangeVerdictString(t *testing.T) {
	cases := map[RangeVerdict]string{
		RangeOutOfRange:  "out_of_range",
		RangeInRange:     "in_range",
		RangeUndecidable: "undecidable",
		RangeVerdict(99): "undecidable", // default
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("RangeVerdict(%d).String() = %q, want %q", v, got, want)
		}
	}
}

func TestBuildConstraintGroup(t *testing.T) {
	cases := []struct {
		li, le, ui, ue string
		want           string
	}{
		{"1.0", "", "", "3.0", ">= 1.0, < 3.0"},
		{"", "1.0", "2.0", "", "> 1.0, <= 2.0"},
		{"0", "", "", "", ""},           // "0" sentinel lower is skipped
		{"", "0", "", "", ""},           // "0" exclusive lower is skipped
		{"", "", "", "", ""},            // nothing
		{" 1.0 ", "", "", "", ">= 1.0"}, // trimmed
	}
	for _, c := range cases {
		if got := BuildConstraintGroup(c.li, c.le, c.ui, c.ue); got != c.want {
			t.Errorf("BuildConstraintGroup(%q,%q,%q,%q) = %q, want %q", c.li, c.le, c.ui, c.ue, got, c.want)
		}
	}
}

func TestStripVersionQualifiers(t *testing.T) {
	cases := map[string]string{
		"8.14.1-r2?arch=x86_64&distro=3.20.2": "8.14.1-r2",
		"2.0#subpath":                         "2.0",
		"2.0":                                 "2.0",
	}
	for in, want := range cases {
		if got := StripVersionQualifiers(in); got != want {
			t.Errorf("StripVersionQualifiers(%q) = %q, want %q", in, got, want)
		}
	}
}

// A range this package cannot PARSE must be undecidable — never "provably out of range".
//
// Found 2026-08-07 writing the TRUST-9 demonstration. `hasUsableConstraint` accepted any non-empty
// token that was not the "none" sentinel, so a malformed range counted as usable; `matchConstraint`
// then returned false for it; `Matches` returned false; and `Applicability` read that as
// **RangeOutOfRange**. The chain turned "we could not parse this" into "provably not affected" —
// which Governance raises as a system not_affected proposal and the shipped D15 policy
// AUTO-ACCEPTS. A malformed feed range would have silently suppressed a live Finding.
//
// The rule is certain in ONE direction only: a parse gap must never drop a vulnerability.
func TestApplicability_UnparseableRangeIsUndecidable(t *testing.T) {
	for _, group := range []string{
		"garbage",          // prose where a comparator belongs
		"not a constraint", // ditto, with spaces
		"affected",         // a feed emitting a status word into a range field
		"none",             // the explicit no-constraint sentinel
		"",                 // empty
		"<",                // an operator with no operand
		">= ",              // ditto, whitespace only
	} {
		r := AffectedRange{Ecosystem: "pypi", Groups: []string{group}}
		if got := r.Applicability("1.26.5"); got != RangeUndecidable {
			t.Errorf("Applicability(group=%q) = %v, want Undecidable — an unparseable range must never read as a verdict", group, got)
		}
	}
}

// The narrowing must not break real ranges: everything the comparator grammar accepts stays
// decidable, or the fix would trade a silent suppression for a silent deferral.
func TestApplicability_RealRangesStayDecidable(t *testing.T) {
	for _, tc := range []struct {
		group     string
		installed string
		want      RangeVerdict
	}{
		{"<2.0.0", "1.26.5", RangeInRange},
		{"<1.0.0", "1.26.5", RangeOutOfRange},
		{">= 1.0, < 2.0", "1.5", RangeInRange},
		{">= 1.0, < 2.0", "2.5", RangeOutOfRange},
		{"1.26.5", "1.26.5", RangeInRange}, // an exact version literal
		{"1.26.5", "1.26.6", RangeOutOfRange},
		{"*", "1.26.5", RangeInRange}, // the explicit wildcard
	} {
		r := AffectedRange{Ecosystem: "pypi", Groups: []string{tc.group}}
		if got := r.Applicability(tc.installed); got != tc.want {
			t.Errorf("Applicability(group=%q, installed=%q) = %v, want %v", tc.group, tc.installed, got, tc.want)
		}
	}
}

// A group mixing a real comparator with an unparseable token is still usable — the real one can be
// evaluated. What must never happen is the reverse: garbage alone deciding anything.
func TestApplicability_MixedGroupUsesTheParsableComparator(t *testing.T) {
	r := AffectedRange{Ecosystem: "pypi", Groups: []string{"<1.0.0, garbage"}}
	if got := r.Applicability("1.26.5"); got == RangeUndecidable {
		t.Error("a group carrying a real comparator must remain decidable")
	}
}
