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

// ClassifierGeneration versions the CLASSIFICATION RULES in this file: NormalizeProduct,
// roleSuffixes, relatedProduct, the generic-token sets and ClassifyClaim. Bump it in the SAME
// change as any edit to those, and the re-classification sweep drains the estate exactly once.
//
// It exists because a rules change advances no card version, so a version-only stamp cannot see
// one. Both carrier fixes in this file shipped invisible for that reason — the role-suffix rule
// (2026-09-16) and the shared-token rule (2026-09-17) each corrected classification for every
// future match while every existing occurrence kept the class the old rules gave it. That is
// KN-VERDICT-2's failure shape, and a constant the sweep can compare against is what closes it.
//
// Generations: 1 = the pre-stamp baseline · 2 = role suffixes kept whole, CPE 2.3 escaping,
// CPE part `a` filter (2026-09-16) · 3 = shared distinguishing token (2026-09-17) ·
// 4 = versioned interpreter wrappers, `python3.12-` (2026-09-17, KN-FIX-5).
const ClassifierGeneration = 4

// distroPrefixes are packaging wrappers a distro puts around an upstream project. They are
// stripped before comparison because NVD names the PROJECT (`pyyaml`) while a component names the
// distro package (`python3-pyyaml`) — neither is derivable from the other in general, but this
// covers the overwhelming majority and anything it misses lands in ClaimUnknown, which is safe.
var distroPrefixes = []string{"python3-", "python3x-", "python-", "python2-", "perl-", "ruby-", "golang-", "rust-", "php-", "nodejs-", "lib"}

// roleSuffixes are packaging ROLE words rather than project names. A distro splits one upstream
// project into sub-packages BY ROLE — `perl-interpreter`, `perl-libs`, `python3-devel` — and the
// tail names the role, not a different project. Stripping the wrapper from those destroys the
// only token that identifies the project at all.
//
// Measured 2026-09-16 (KN-CLAIM-1 variant B): the card for a perl CVE carried the carrier `perl`,
// correct and sometimes the ONLY entry, while `perl-interpreter` normalized to `interpreter` and
// matched nothing. The evidence was right and the normalization threw it away.
//
// This is VOCABULARY, not data. Packaging roles are a small closed set; project names are not.
// That is the line an alias table (`http_server` → `httpd`) crosses and this does not.
//
// Keeping the name whole is the FAIL-SAFE direction in every consumer: classification errs
// toward carrier (the safe way), while MatchesFixPackage and the inferred bridge both demand
// EQUALITY, so a longer name under-matches rather than over-matches.
var roleSuffixes = map[string]struct{}{
	"interpreter": {}, "libs": {}, "devel": {}, "common": {}, "core": {},
	"doc": {}, "docs": {}, "tools": {}, "utils": {}, "bin": {},
	"static": {}, "headers": {}, "lang": {}, "macros": {},
}

// NormalizeProduct reduces a package or CPE product name to a comparable form: lowercase, `_`
// folded to `-`, and one distro wrapper prefix removed — UNLESS what the strip would leave is a
// packaging role rather than a project (see roleSuffixes), in which case the name is kept whole.
//
// It is deliberately conservative — it never strips more than one prefix and never guesses a
// suffix — because the cost of a WRONG equality here is classifying a carrier as scope, which is
// the one direction that could hide a real vulnerability. Under-matching yields ClaimUnknown,
// which every consumer treats as carrier.
func NormalizeProduct(s string) string {
	n := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
	pre := wrapperPrefixOf(n)
	if pre == "" {
		return n
	}
	root := strings.TrimPrefix(n, pre)
	if _, isRole := roleSuffixes[root]; isRole {
		// `perl-interpreter` IS perl; `python3-pyyaml` is not python. The difference is whether
		// the tail names a role or a project, and only the first may keep the wrapper — which
		// is precisely what lets `python3-pyyaml` stay scope.
		return n
	}
	return root
}

// wrapperFamily groups the distro wrapper prefixes whose members name the SAME upstream
// project when their bare roots agree: every python-era wrapper is one family, each other
// wrapper its own. It exists for MatchesFixPackage's guard (D12): `python3-json` and
// `ruby-json` both normalize to `json`, and without the family check a ruby bound could
// answer a python query on a shared rpm card — a version compare over two unrelated version
// lines, which is how a false "fixed" would be minted.
//
// Matched by STEM rather than by literal, so every versioned interpreter wrapper
// (`python3.12-`, `python3.9-`) joins the family it belongs to without being enumerated.
func wrapperFamily(prefix string) string {
	if strings.HasPrefix(prefix, "python") {
		return "python"
	}
	return prefix // each remaining wrapper (perl-, ruby-, lib, …) is its own family
}

// versionedInterpreterPrefix matches a wrapper whose interpreter version is IN the prefix —
// `python3.12-pip`, `python3.9-devel` — and returns that prefix, or "" when the name is not of
// that shape (KN-FIX-5, measured 2026-09-10 on the KN-FIX-4 live verification).
//
// A literal list cannot express this. `distroPrefixes` holds `python3-` and `python3x-`, and
// `python3.12-pip` fails HasPrefix on both (a dot where the hyphen belongs), so the name went
// through unstripped: the D3 bridge's name affinity failed and
// MatchesFixPackage("pip", "python3.12-pip") compared the bare root `pip` against the whole
// `python3.12-pip`. Measured consequence: the KN-FIX-4 pass cleared the setuptools shadow via
// its sibling `python3-setuptools` and left every `pip@23.2.1` shadow open beside its
// at-version sibling `python3.12-pip@23.2.1-4.el8`.
//
// One dynamic rule instead of literals that grow with every interpreter release. It is
// deliberately narrow: the stem must be a known interpreter, the version may only be digits
// and dots, and a trailing hyphen with something after it is required — so `python3` alone,
// `pythonista-foo` and `python-3-foo` are all left to the literal list or to no rule at all.
func versionedInterpreterPrefix(n string) string {
	for _, stem := range versionedInterpreterStems {
		if !strings.HasPrefix(n, stem) {
			continue
		}
		rest := n[len(stem):]
		digits := 0
		for i, r := range rest {
			switch {
			case r >= '0' && r <= '9':
				digits++
			case r == '.':
			case r == '-':
				// A wrapper needs a version and a payload: `python3.12-` alone strips to
				// nothing, and stripping to the empty string loses the name entirely.
				if digits > 0 && i+1 < len(rest) {
					return n[:len(stem)+i+1]
				}
				return ""
			default:
				return "" // not a pure version segment — not this rule's shape
			}
		}
		return ""
	}
	return ""
}

// versionedInterpreterStems are the interpreters whose distro packages carry the version in
// the wrapper. Only python is measured; the list exists so adding one is a one-line change
// rather than another parser.
var versionedInterpreterStems = []string{"python"}

// wrapperPrefixOf returns the distro wrapper that applies to an already-lowercased,
// underscore-folded name, or "" when none does.
//
// ONE definition, shared by NormalizeProduct and strippedWrapper. They previously each carried
// the rule, and the comment on strippedWrapper warned that a divergence between them would
// compare a stripped root against an unstripped one — a hazard that disappears when there is
// only one place to change.
func wrapperPrefixOf(n string) string {
	if pre := versionedInterpreterPrefix(n); pre != "" {
		return pre
	}
	for _, pre := range distroPrefixes {
		if len(n) > len(pre) && strings.HasPrefix(n, pre) {
			return pre
		}
	}
	return ""
}

// strippedWrapper reports which distro wrapper NormalizeProduct would strip from the
// (already lowercased, underscore-folded) name — "" when none applies. It must agree with
// NormalizeProduct exactly, role suffixes included, or MatchesFixPackage compares a stripped
// root against an unstripped one.
func strippedWrapper(n string) string {
	pre := wrapperPrefixOf(n)
	if pre == "" {
		return ""
	}
	if _, isRole := roleSuffixes[strings.TrimPrefix(n, pre)]; isRole {
		return "" // kept whole by NormalizeProduct, so no wrapper was stripped
	}
	return pre
}

// MatchesFixPackage reports whether a card's fix-attribution package name answers a query for
// the given component package (EDR-VEX-01 D12, KN-FIX-4). Exact case-insensitive equality
// first — the rule that always held; then normalized-name EQUALITY (never containment: a
// `python3-pip-wheel` bound must not clear `python3-pip`, and a wrong clearance is a false
// negative) guarded by wrapper-family compatibility: the bare roots must agree AND the
// stripped wrappers must be the same family or one side bare. The bare-vs-wrapped direction
// is the measured true-positive shape — the vendor files under its project name (`PyYAML`,
// `curl`) or its source name (`python-setuptools`) while the SBOM carries the binary name
// (`python3-pyyaml`, `libcurl`, `python3-setuptools`); reproduced live 2026-09-10, where the
// exact-only rule left `FixesFor("python3-setuptools")` empty beside the exact bound the
// card held under `python-setuptools`.
func MatchesFixPackage(fixPkg, queryPkg string) bool {
	f := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(fixPkg)), "_", "-")
	q := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(queryPkg)), "_", "-")
	if f == "" || q == "" {
		return false
	}
	if f == q {
		return true
	}
	fw, qw := strippedWrapper(f), strippedWrapper(q)
	if strings.TrimPrefix(f, fw) != strings.TrimPrefix(q, qw) {
		return false // different bare roots — different projects
	}
	if fw == "" || qw == "" {
		return true // bare project/source name vs the distro's wrapped binary name
	}
	return wrapperFamily(fw) == wrapperFamily(qw)
}

// minProductOverlap is the shortest normalized name allowed to match by CONTAINMENT. Below it a
// substring match is coincidence rather than evidence — `jq` inside `jquery` is the shape it
// forbids. It deliberately does NOT gate token overlap, where a whole token standing alone is
// evidence in a way a bare substring never is.
const minProductOverlap = 3

// minTokenLen is the shortest token allowed to stand as evidence by itself. It admits the real
// two-character projects (`jq`, `xz`) that the containment floor locks out, while still rejecting
// the single-character debris that reaches carrier lists from malformed CPE records — a literal
// `\` was measured on two cards, 2026-09-16.
const minTokenLen = 2

// extraGenericTokens are packaging-structure words that appear inside many unrelated project
// names. A shared token is evidence of a shared project only when the token DISTINGUISHES
// something: `spring-framework` and `spring-core` share `spring`, which is a project name, while
// `spring-core` and `openssl-core` share `core`, which is a packaging role and says nothing.
// Without this filter, token overlap would make every `-server`, `-core` and `-libs` package a
// carrier of every other one's flaws — over-matching so broad that `claim_class` would stop
// discriminating at all, which is the one way this function can fail usefully AND silently.
//
// Every roleSuffixes word is generic by construction — they ARE packaging roles — so this set
// only adds the structure words that are not wrapper-strip candidates.
//
// Language names are deliberately ABSENT. A language token survives normalization only in the
// role-protected case (`perl-libs`, `python3-devel`), and that case is exactly a true positive;
// marking `perl` generic would throw away the evidence the role rule was added to keep.
var extraGenericTokens = map[string]struct{}{
	"server": {}, "client": {}, "daemon": {}, "agent": {}, "service": {}, "runtime": {},
	"framework": {}, "engine": {}, "library": {}, "libraries": {}, "module": {}, "modules": {},
	"plugin": {}, "plugins": {}, "driver": {}, "drivers": {}, "api": {}, "sdk": {}, "cli": {},
	"gui": {}, "web": {}, "app": {}, "apps": {}, "base": {}, "main": {}, "minimal": {},
	"full": {}, "extras": {}, "compat": {}, "legacy": {}, "data": {}, "config": {}, "conf": {},
	"source": {}, "src": {}, "dev": {}, "test": {}, "tests": {}, "examples": {}, "samples": {},
	"man": {}, "locale": {}, "debug": {}, "debuginfo": {}, "debugsource": {}, "selinux": {},
	"systemd": {}, "init": {}, "scripts": {}, "bindings": {}, "filesystem": {}, "all": {},
	"util": {}, "tool": {},
}

// isGenericToken reports whether a token is packaging vocabulary rather than a project name.
func isGenericToken(t string) bool {
	if _, isRole := roleSuffixes[t]; isRole {
		return true
	}
	_, isGeneric := extraGenericTokens[t]
	return isGeneric
}

// distinguishingTokens splits a normalized name on `-` and keeps only the tokens that could
// identify a project at all.
func distinguishingTokens(n string) []string {
	var out []string
	for _, t := range strings.Split(n, "-") {
		if len(t) < minTokenLen || isGenericToken(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// sharesDistinguishingToken reports whether two normalized names have a project-identifying
// token in common. Names carry one to four tokens, so the nested scan is cheaper than building
// a set.
func sharesDistinguishingToken(a, b string) bool {
	at := distinguishingTokens(a)
	if len(at) == 0 {
		return false // nothing but packaging vocabulary — no claim either way
	}
	bt := distinguishingTokens(b)
	for _, x := range at {
		for _, y := range bt {
			if x == y {
				return true
			}
		}
	}
	return false
}

// relatedProduct reports whether two normalized names describe the same project.
//
// It is deliberately ASYMMETRIC IN RISK: equality, containment OR a shared distinguishing token
// counts, so it errs toward CARRIER. A distro splits an upstream project across packages that
// keep its name as a stem — `vim` -> `vim-minimal`, `openssl` -> `openssl-libs` — and NVD names
// the project while a vendor prefixes it (`commons-beanutils` vs `apache-commons-beanutils`).
// Demanding exact equality classified `apache-commons-beanutils` as SCOPE for its own CVE.
//
// Over-matching costs precision: a bystander stays a carrier and nothing improves for it.
// Under-matching would mark a genuinely vulnerable package as `scope`, and a consumer acting on
// that could drop it from a plan. Only one of those hides a vulnerability, so the comparison
// leans the other way.
//
// The token rule (KN-CLAIM-1 variant C, measured 2026-09-17) closes two shapes containment
// cannot reach, both of them SIBLING packages of one upstream project:
//
//   - a shared stem with divergent tails — `spring_framework` (NVD) vs `spring-core` /
//     `spring-web` (the SBOM). Neither string contains the other, so containment called the
//     framework's own CVEs `scope` on 20 findings. This is not a distro problem: the components
//     are maven, with a single clean carrier.
//   - a project name below the containment floor — `xz` vs `xz-libs`. Two-character projects
//     (`jq`, `xz`, `mc`, `bc`) could previously match ONLY their own exact name, so every
//     sub-package of one was silently scope.
//
// What it deliberately does NOT do is bridge a SYNONYM: `http_server` (NVD's CPE product) and
// `httpd` (the package) share no token, and no amount of string comparison can relate them.
// That is a vocabulary/identity problem and it belongs to the intake identity model (EDR-1),
// not here — the same line the roleSuffixes comment draws around an alias table.
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
	if len(short) >= minProductOverlap && strings.Contains(long, short) {
		return true
	}
	return sharesDistinguishingToken(a, b)
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
