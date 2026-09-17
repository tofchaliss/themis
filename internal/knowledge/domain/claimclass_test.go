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

// KN-CLAIM-1 variant C, measured 2026-09-17. Containment can only relate two names when one is
// a substring of the other, which is false for SIBLING packages of one upstream project. Both
// shapes below were measured against the live estate; the guards are the over-matching this rule
// would otherwise introduce.
func TestClassifyClaimSharedTokenRelatesSiblingPackages(t *testing.T) {
	for _, tc := range []struct {
		name          string
		carriers      []string
		pkg, compName string
		want          domain.ClaimClass
	}{
		// Shape 1: a shared stem with divergent tails. Not a distro problem — these components
		// are maven, with one clean carrier, and containment called them scope on 20 findings.
		{"spring-core is the spring framework",
			[]string{"spring_framework"}, "spring-core", "spring-core", domain.ClaimCarrier},
		{"and so is spring-web",
			[]string{"spring_framework"}, "spring-web", "spring-web", domain.ClaimCarrier},
		// Shape 2: a project name below the containment floor. `xz` is two characters, so it
		// could previously match ONLY the literal name `xz` — every sub-package was scope.
		{"xz-libs carries an xz flaw despite the two-character project name",
			[]string{"xz"}, "xz-libs", "xz-libs", domain.ClaimCarrier},
		{"an accepted over-match: xz-java shares the token and stays carrier (errs safe)",
			[]string{"xz"}, "xz-java", "xz-java", domain.ClaimCarrier},
		{"but an unrelated two-character project is still scope",
			[]string{"jq"}, "jansson", "jansson", domain.ClaimScope},

		// The guards. A shared token is evidence only when the token distinguishes something;
		// without the generic filter every `-core`/`-server` package would carry every other
		// one's flaws, and claim_class would stop discriminating at all.
		{"a shared packaging ROLE is not evidence: spring-framework vs openssl-core",
			[]string{"spring-framework"}, "openssl-core", "openssl-core", domain.ClaimScope},
		{"nor is a shared structure word: http-server vs nginx-server",
			[]string{"http-server"}, "nginx-server", "nginx-server", domain.ClaimScope},
		{"a carrier made only of packaging vocabulary claims nothing",
			[]string{"core"}, "server", "server", domain.ClaimScope},
		{"single-character CPE debris stays inert — a literal backslash was measured on 2 cards",
			[]string{"\\"}, "httpd", "httpd", domain.ClaimScope},

		// The guard that must survive every change to this file: a module-stream rebuild lists
		// pyyaml, which is a PROJECT, so it still strips and still fails to relate to `python`.
		{"role rule + token rule must not leak: python3-pyyaml against python is still scope",
			[]string{"python"}, "python3-pyyaml", "python3-pyyaml", domain.ClaimScope},

		// The containment path is RETAINED, so everything that matched before still matches.
		{"containment still relates a role sub-package to its bare project",
			[]string{"perl"}, "perl-libs", "perl-libs", domain.ClaimCarrier},
		{"and still relates a stem sub-package",
			[]string{"vim"}, "", "vim-minimal", domain.ClaimCarrier},

		// The EDR-1 BOUNDARY, asserted on purpose. `http_server` and `httpd` share no token and
		// no substring: this is a SYNONYM, which no string comparison can bridge. It belongs to
		// the intake identity model. If a future change makes this pass HERE, it has grown an
		// alias table inside the correlation vocabulary — read EDR-1 before deleting this case.
		{"httpd stays scope: a synonym is an identity problem, not a string problem",
			[]string{"debian_linux", "fedora", "http_server"}, "httpd", "httpd", domain.ClaimScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.ClassifyClaim(tc.carriers, tc.pkg, tc.compName); got != tc.want {
				t.Errorf("ClassifyClaim(%v, %q, %q) = %q, want %q",
					tc.carriers, tc.pkg, tc.compName, got, tc.want)
			}
		})
	}
}

// KN-FIX-5, measured 2026-09-10 on the KN-FIX-4 live verification: `distroPrefixes` holds the
// literals `python3-` and `python3x-`, and `python3.12-pip` fails HasPrefix on both — a dot
// where the hyphen belongs. The name went through unstripped, so the bridge's name affinity
// failed and the fix lookup compared the bare root `pip` against the whole `python3.12-pip`.
// The KN-FIX-4 pass cleared the setuptools shadow through its sibling and left every
// `pip@23.2.1` shadow open beside `python3.12-pip@23.2.1-4.el8`.
//
// One dynamic rule, deliberately narrow — every "must be left alone" case below is a branch of
// it, and each one falls back to the literal list or to no rule at all.
func TestNormalizeProductStripsVersionedInterpreterWrappers(t *testing.T) {
	for _, c := range []struct{ in, want, why string }{
		{"python3.12-pip", "pip", "the measured case"},
		{"python3.12-pyyaml", "pyyaml", "and it still strips a project tail, so the guard holds"},
		{"python3.9-setuptools", "setuptools", "any interpreter version, not an enumerated list"},
		{"python3.9-devel", "python3.9-devel", "a ROLE tail keeps the whole name, as with python3-devel"},
		{"python3.12-", "python3.12-", "a wrapper with no payload must not strip to nothing"},
		{"python3", "python3", "no hyphen at all is not a wrapper"},
		{"pythonista-foo", "pythonista-foo", "the version segment must be digits and dots only"},
		{"python3-pip", "pip", "the literal list still applies where it always did"},
		{"libssl", "ssl", "an unrelated wrapper is untouched"},
	} {
		if got := domain.NormalizeProduct(c.in); got != c.want {
			t.Errorf("NormalizeProduct(%q) = %q, want %q — %s", c.in, got, c.want, c.why)
		}
	}
}

// The fix lookup is what the defect actually broke, and the family guard must survive the
// dynamic rule: matching by STEM rather than by literal is what keeps `python3.12-` in the
// python family instead of becoming a family of its own.
func TestMatchesFixPackageVersionedInterpreterWrappers(t *testing.T) {
	for _, c := range []struct {
		fix, query string
		want       bool
		why        string
	}{
		{"pip", "python3.12-pip", true, "the measured pair: vendor project name vs versioned binary"},
		{"python3-pip", "python3.12-pip", true, "same python family, different wrapper generation"},
		{"python3.12-pip", "python3.9-pip", true, "two interpreter versions of one project"},
		{"ruby-json", "python3.12-json", false, "COLLISION GUARD: the stem match must not merge families"},
		{"pip", "python3.12-pip-wheel", false, "containment is still never equality"},
		{"pip", "python3.12-", false, "a payload-less wrapper matches nothing"},
	} {
		if got := domain.MatchesFixPackage(c.fix, c.query); got != c.want {
			t.Errorf("MatchesFixPackage(%q,%q) = %v, want %v — %s", c.fix, c.query, got, c.want, c.why)
		}
	}
}

// The classification consequence, since NormalizeProduct is shared (the entry warned not to
// assume this was free). The bystander guard must survive the versioned wrapper exactly as it
// survives the plain one.
func TestClassifyClaimVersionedInterpreterWrappers(t *testing.T) {
	for _, c := range []struct {
		name      string
		carriers  []string
		pkg, comp string
		want      domain.ClaimClass
	}{
		{"a versioned module-stream bystander is still scope",
			[]string{"python"}, "python3.12-pyyaml", "python3.12-pyyaml", domain.ClaimScope},
		{"a versioned ROLE package is still the interpreter",
			[]string{"python"}, "python3.12-devel", "python3.12-devel", domain.ClaimCarrier},
		{"and the real carrier resolves through the versioned wrapper",
			[]string{"pip"}, "python3.12-pip", "python3.12-pip", domain.ClaimCarrier},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := domain.ClassifyClaim(c.carriers, c.pkg, c.comp); got != c.want {
				t.Errorf("ClassifyClaim = %q, want %q", got, c.want)
			}
		})
	}
}
