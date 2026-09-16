package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// EDR-CORRELATION-01 D3/D4. The live case this exists for: CVE-2019-10086 is Apache Commons
// BeanUtils, and `javapackages-filesystem` was rebuilt alongside it in the same module stream. The
// AI was asked about the CVE, handed that component, and wrote — at confidence 0.95 — that the CVE
// "affects the Java packages filesystem component". Grounding Verification passed it, because the
// projection genuinely listed it.
func TestClassifyClaim(t *testing.T) {
	for _, tc := range []struct {
		name          string
		carriers      []string
		pkg, compName string
		want          domain.ClaimClass
	}{
		{"no carriers known → unknown, never scope",
			nil, "javapackages-filesystem", "javapackages-filesystem", domain.ClaimUnknown},
		{"the live bystander",
			[]string{"commons-beanutils"}, "javapackages-filesystem", "javapackages-filesystem", domain.ClaimScope},
		{"the real carrier",
			[]string{"commons-beanutils"}, "apache-commons-beanutils", "apache-commons-beanutils", domain.ClaimCarrier},
		{"distro wrapper stripped: NVD says pyyaml, the component is python3-pyyaml",
			[]string{"pyyaml"}, "PyYAML", "python3-pyyaml", domain.ClaimCarrier},
		{"underscore folded: NVD's commons_beanutils",
			[]string{"commons_beanutils"}, "commons-beanutils", "commons-beanutils", domain.ClaimCarrier},
		{"a distro subpackage keeps its project as a stem: vim-minimal ships the vim binary",
			[]string{"vim"}, "", "vim-minimal", domain.ClaimCarrier},
		{"a vendor prefix must not demote the real carrier",
			[]string{"commons-beanutils"}, "apache-commons-beanutils", "apache-commons-beanutils", domain.ClaimCarrier},
		{"but an unrelated name is still scope — containment is not a licence to match anything",
			[]string{"commons-beanutils"}, "openssh", "openssh-server", domain.ClaimScope},
		{"one carrier among several",
			[]string{"urllib3", "pyyaml"}, "PyYAML", "python3-pyyaml", domain.ClaimCarrier},
		// KN-CLAIM-1 variant B, measured 2026-09-16: the carrier `perl` was present and correct
		// on the card — sometimes the ONLY entry — and the wrapper strip turned the component
		// into `interpreter`, which matches nothing. The role suffix keeps the project token.
		{"role sub-package IS the project: perl-interpreter carries a perl flaw",
			[]string{"perl"}, "perl-interpreter", "perl-interpreter", domain.ClaimCarrier},
		{"role sub-package, libs: perl-libs carries a perl flaw",
			[]string{"perl"}, "perl-libs", "perl-libs", domain.ClaimCarrier},
		{"the same card's real bystander stays scope — Encode is a project, not a role",
			[]string{"perl"}, "perl-Encode", "perl-Encode", domain.ClaimScope},
		{"the polluted carrier list still resolves: perl among NVD's OS products",
			[]string{"enterprise_linux", "fedora", "perl"}, "perl-libs", "perl-libs", domain.ClaimCarrier},
		// The guard the role rule must NOT break: a python module-stream rebuild lists pyyaml,
		// which is a PROJECT and therefore still strips. Comparing the unstripped form here
		// would make every bystander a carrier — the defect EDR-CORRELATION-01 exists to stop.
		{"role rule must not leak: python3-pyyaml against carrier python is still scope",
			[]string{"python"}, "python3-pyyaml", "python3-pyyaml", domain.ClaimScope},
		{"and python3-devel against carrier python IS the project",
			[]string{"python"}, "python3-devel", "python3-devel", domain.ClaimCarrier},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.ClassifyClaim(tc.carriers, tc.pkg, tc.compName); got != tc.want {
				t.Errorf("ClassifyClaim(%v, %q, %q) = %q, want %q", tc.carriers, tc.pkg, tc.compName, got, tc.want)
			}
		})
	}
}

// Unknown must behave as carrier everywhere. A gap in evidence cannot be allowed to hide a live
// vulnerability — the same fail-safe direction as A1's RangeUndecidable.
func TestClaimClassActsAsCarrier(t *testing.T) {
	if !domain.ClaimUnknown.ActsAsCarrier() {
		t.Error("unknown must act as carrier — absence of evidence is not evidence of absence")
	}
	if !domain.ClaimCarrier.ActsAsCarrier() {
		t.Error("carrier must act as carrier")
	}
	if domain.ClaimScope.ActsAsCarrier() {
		t.Error("scope must NOT act as carrier — that is the whole point of recording it")
	}
}

func TestNormalizeProductStripsOneWrapperOnly(t *testing.T) {
	// Conservative on purpose: stripping more than one prefix, or guessing suffixes, risks
	// classifying a real carrier as scope — the one direction that could hide a vulnerability.
	if got := domain.NormalizeProduct("python3-libxml2"); got != "libxml2" {
		t.Errorf("NormalizeProduct = %q, want libxml2", got)
	}
	if got := domain.NormalizeProduct("libssl"); got != "ssl" {
		t.Errorf("NormalizeProduct = %q, want ssl", got)
	}
	// A prefix that IS the whole name must not normalize to empty.
	if got := domain.NormalizeProduct("perl-"); got != "perl-" {
		t.Errorf("NormalizeProduct = %q, want the input unchanged", got)
	}
}

// A distro splits one project into sub-packages BY ROLE. Stripping the wrapper from those
// leaves a role word that identifies nothing, which is how a correct carrier was thrown away
// (KN-CLAIM-1 variant B, measured 2026-09-16).
func TestNormalizeProductKeepsRoleSuffixesWhole(t *testing.T) {
	for _, c := range []struct{ in, want, why string }{
		{"perl-interpreter", "perl-interpreter", "the measured case: `interpreter` names a role"},
		{"perl-libs", "perl-libs", "so does `libs`"},
		{"python3-devel", "python3-devel", "and `devel`"},
		{"PYTHON3-DOC", "python3-doc", "case folding still applies to a kept name"},
		{"python3_common", "python3-common", "underscore folding too"},
		{"python3-pyyaml", "pyyaml", "a PROJECT tail still strips — this is the guard"},
		{"python3-libxml2", "libxml2", "and so does this one"},
		{"libssl", "ssl", "`ssl` is a project, not a role"},
		{"libs", "s", "a bare role word is not itself wrapper-protected"},
	} {
		if got := domain.NormalizeProduct(c.in); got != c.want {
			t.Errorf("NormalizeProduct(%q) = %q, want %q — %s", c.in, got, c.want, c.why)
		}
	}
}

// D12 (KN-FIX-4): the fix-lookup name rule — exact first, then normalized EQUALITY under the
// wrapper-family guard, never containment. Every pair below is either measured from the
// 2026-09-10 MRF case or the collision that guard exists to forbid.
func TestMatchesFixPackage(t *testing.T) {
	cases := []struct {
		fix, query string
		want       bool
		why        string
	}{
		{"httpd", "httpd", true, "exact match is untouched"},
		{"Python-Setuptools", "python_setuptools", true, "case + underscore folding, as everywhere"},
		{"python-setuptools", "python3-setuptools", true, "the measured pair: source name vs binary name, one python family"},
		{"PyYAML", "python3-pyyaml", true, "vendor project name vs wrapped binary (bare-vs-wrapped)"},
		{"python-ply", "python3-ply", true, "same family, different wrapper generation"},
		{"curl", "libcurl", true, "bare source vs lib-wrapped binary (the libcurl/nghttp2/attr class)"},
		{"nghttp2", "libnghttp2", true, "same class"},
		{"ruby-json", "python3-json", false, "COLLISION GUARD: same bare root, different language families"},
		{"perl-JSON", "python3-json", false, "collision guard, perl side"},
		{"python3-pip-wheel", "python3-pip", false, "containment is never equality — a -wheel bound must not clear pip"},
		{"python3-pip", "python3-pip-wheel", false, "nor the other direction"},
		{"openssl", "openssl-libs", false, "distro sub-package split is NOT a name-wrapper — stays for source attribution"},
		{"", "httpd", false, "empty never matches"},
		{"httpd", "", false, "empty never matches"},
		{"lib", "lib", true, "a name equal to a bare prefix matches only itself (len guard in strippedWrapper)"},
		// strippedWrapper must agree with NormalizeProduct about role suffixes, or a stripped
		// root gets compared against an unstripped one.
		{"libs", "perl-libs", false, "a fix for a package literally named `libs` must not answer perl-libs"},
		{"perl", "perl-libs", false, "and a bare `perl` bound is not a fix for the libs sub-package"},
		{"perl-libs", "perl-libs", true, "the role-suffixed name still matches itself exactly"},
	}
	for _, c := range cases {
		if got := domain.MatchesFixPackage(c.fix, c.query); got != c.want {
			t.Errorf("MatchesFixPackage(%q,%q) = %v, want %v — %s", c.fix, c.query, got, c.want, c.why)
		}
	}
}
