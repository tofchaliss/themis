package domain

import "strings"

// ClaimClass records WHY a component matched a Faultline (EDR-CORRELATION-01 D3).
//
// A distro module-stream advisory rebuilds every RPM in the stream and lists them all as
// affected. Read as N vulnerability claims, that makes a CPython flaw a vulnerability of
// `python3-pyyaml`. Read correctly, it is ONE claim whose package list is SCOPE.
//
// The distinction is RECORDED rather than resolved by deletion (D2): the old build genuinely does
// need replacing, so dropping the match would delete real work. What changes is what a consumer
// may say about it.
type ClaimClass string

const (
	// ClaimCarrier — evidence says this package carries the flaw.
	ClaimCarrier ClaimClass = "carrier"
	// ClaimScope — this package was in the advisory's rebuild set, with no evidence it carries
	// the flaw. Still work; not a vulnerability OF this package.
	ClaimScope ClaimClass = "scope"
	// ClaimUnknown — no attribution evidence available.
	//
	// Every consumer treats it as ClaimCarrier. A gap in evidence must never hide a live
	// vulnerability — the same fail-safe direction as A1's RangeUndecidable and D2.
	ClaimUnknown ClaimClass = ""
)

// ActsAsCarrier reports whether a consumer must treat this class as carrying the flaw. Unknown
// counts, deliberately: absence of evidence is not evidence of absence.
func (c ClaimClass) ActsAsCarrier() bool { return c != ClaimScope }

// distroPrefixes are packaging wrappers a distro puts around an upstream project. They are
// stripped before comparison because NVD names the PROJECT (`pyyaml`) while a component names the
// distro package (`python3-pyyaml`) — neither is derivable from the other in general, but this
// covers the overwhelming majority and anything it misses lands in ClaimUnknown, which is safe.
var distroPrefixes = []string{"python3-", "python3x-", "python-", "python2-", "perl-", "ruby-", "golang-", "rust-", "php-", "nodejs-", "lib"}

// NormalizeProduct reduces a package or CPE product name to a comparable form: lowercase, `_`
// folded to `-`, and one distro wrapper prefix removed.
//
// It is deliberately conservative — it never strips more than one prefix and never guesses a
// suffix — because the cost of a WRONG equality here is classifying a carrier as scope, which is
// the one direction that could hide a real vulnerability. Under-matching yields ClaimUnknown,
// which every consumer treats as carrier.
func NormalizeProduct(s string) string {
	n := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
	for _, pre := range distroPrefixes {
		if len(n) > len(pre) && strings.HasPrefix(n, pre) {
			return strings.TrimPrefix(n, pre)
		}
	}
	return n
}

// minProductOverlap is the shortest normalized name allowed to match by containment. Below it a
// substring match is coincidence rather than evidence.
const minProductOverlap = 3

// relatedProduct reports whether two normalized names describe the same project.
//
// It is deliberately ASYMMETRIC IN RISK: equality OR containment counts, so it errs toward
// CARRIER. A distro splits an upstream project across packages that keep its name as a stem —
// `vim` → `vim-minimal`, `openssl` → `openssl-libs` — and NVD names the project while a vendor
// prefixes it (`commons-beanutils` vs `apache-commons-beanutils`). Demanding exact equality
// classified `apache-commons-beanutils` as SCOPE for its own CVE.
//
// Over-matching costs precision: a bystander stays a carrier and nothing improves for it.
// Under-matching would mark a genuinely vulnerable package as `scope`, and a consumer acting on
// that could drop it from a plan. Only one of those hides a vulnerability, so the comparison
// leans the other way.
func relatedProduct(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	short, long := a, b
	if len(short) > len(long) {
		short, long = long, short
	}
	return len(short) >= minProductOverlap && strings.Contains(long, short)
}

// ClassifyClaim decides what a component's match MEANS, given the products a flaw-describing
// source says carry it.
//
// No carriers known → ClaimUnknown for everything: with nothing to compare against, calling a
// component `scope` would be an assertion the evidence does not support.
func ClassifyClaim(carriers []string, componentPackage, componentName string) ClaimClass {
	if len(carriers) == 0 {
		return ClaimUnknown
	}
	for _, want := range []string{componentPackage, componentName} {
		n := NormalizeProduct(want)
		for _, c := range carriers {
			if relatedProduct(NormalizeProduct(c), n) {
				return ClaimCarrier
			}
		}
	}
	return ClaimScope
}
