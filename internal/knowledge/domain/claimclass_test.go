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
