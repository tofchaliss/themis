package value

import "strings"

// Product scope, and whether a vendor statement applies to a release (EDR-VEX-02 D3–D6).
//
// A vendor's VEX statement covers a PRODUCT. Themis's question is different: does that product
// scope cover the release in front of us? Those are two separate facts and this file computes
// only the second — the vendor's own assertion is never touched (D1).

// ProductScope is a product identity reduced to the two things applicability is evaluated on: a
// distribution/product FAMILY and a MAJOR version. A zero Family means the scope could not be
// established, which is deliberately distinct from establishing a scope that does not match.
type ProductScope struct {
	Family string
	Major  string
}

// FamilyEnterpriseLinux is the RHEL-compatible family: Red Hat Enterprise Linux and its 1:1
// rebuilds (Rocky, Alma). It is ONE family because an `elN`-tagged rpm from any of them carries
// the same fix line — the equivalence EDR-VEX-01 D11 already relies on (the rocky feed skips
// RLSA as an RHSA clone) and that RPMReleaseMajor already encodes.
const FamilyEnterpriseLinux = "enterprise-linux"

// Known reports whether a scope was established at all.
func (s ProductScope) Known() bool { return s.Family != "" && s.Major != "" }

// ScopeMatch is Themis's determination about a vendor scope against a release (D3).
type ScopeMatch string

const (
	// ScopeApplicable — the scope positively matches the release.
	ScopeApplicable ScopeMatch = "applicable"
	// ScopeNotApplicable — the scope is positively KNOWN and does not match.
	ScopeNotApplicable ScopeMatch = "not_applicable"
	// ScopeUnknown — the VENDOR'S STATEMENT could not be placed: no CPE, or one Themis cannot
	// classify.
	//
	// EPISTEMIC UNCERTAINTY, never product mismatch (D4). "I know this does not apply" and "I
	// cannot determine whether this applies" are different statements, and collapsing the second
	// into the first would hide a broken resolver behind reasonable-looking numbers.
	ScopeUnknown ScopeMatch = "unknown"
	// ScopeNotComparable — the vendor's scope WAS placed; the RELEASE was not, so the two cannot
	// be compared at all (D11).
	//
	// This is the fourth state because `unknown` was carrying two facts with different
	// information value, which is D4's own mistake one level down. Measured 2026-09-21: a Maven
	// `spring-web` Finding reported six identical `unknown`s against Red Hat statements naming
	// "Red Hat build of Apache Camel 4 for Quarkus 3" — an unambiguous product. Red Hat had been
	// perfectly clear; Themis could not place its own release, because a Maven artifact carries
	// no `elN` build and nothing else says which distribution major it is.
	//
	// Those two need different reactions. A reviewer dismisses "the vendor spoke about a builder
	// image and this is a Java library" instantly; an unreadable CPE is a feed-quality gap that
	// permits no conclusion. Reported as one word, neither is actionable.
	//
	// It is ONE-SIDED and therefore UNIFORM: vendor-known + release-known always resolves through
	// family/major, so the only route here is a release that cannot be placed — which is a fact
	// about the Finding, not about any statement. Every statement on such a Finding reports it,
	// and that repetition is the signal, not noise.
	//
	// Like every non-applicable state it CANNOT clear a Finding: the governance checks compare
	// against ScopeApplicable, so absent evidence never suppresses.
	ScopeNotComparable ScopeMatch = "not_comparable"
)

// MatchScope determines whether a vendor product scope covers a release's own scope (D3/D6).
//
// Family is compared BEFORE major, which is not a micro-optimisation but D5's rule: a scope must
// be classified before any version it carries is interpreted. `cpe:/a:redhat:openshift_pipelines:1`
// has a perfectly valid version of `1` that has nothing to do with an OS major, so comparing
// majors first would read it as "major 1" and decide against an operating-system release.
// The two unplaceable cases are kept APART (D11), and the vendor side is tested first so each
// word means exactly one thing: `unknown` is always "the vendor's statement could not be placed",
// and `not_comparable` is always "the statement was placed, our release was not". When BOTH fail,
// `unknown` wins — an unreadable statement is a fact about the evidence, and evidence that cannot
// be read is the more fundamental gap.
func MatchScope(vendor, release ProductScope) ScopeMatch {
	if !vendor.Known() {
		return ScopeUnknown // the statement itself cannot be placed — say nothing more
	}
	if !release.Known() {
		return ScopeNotComparable // the statement is placed; there is nothing here to place it against
	}
	if vendor.Family != release.Family {
		return ScopeNotApplicable // a different product — established, not uncertain
	}
	if vendor.Major != release.Major {
		return ScopeNotApplicable
	}
	return ScopeApplicable
}

// cpeProductVersion pulls the PRODUCT and VERSION out of a CPE, accepting both forms Themis
// meets: the 2.2 URI (`cpe:/a:redhat:openshift_pipelines:1`) that Red Hat's security data uses,
// and the 2.3 formatted string (`cpe:2.3:o:redhat:enterprise_linux:8:*:…`). Returns empty
// strings when the shape is not recognisable, which becomes ScopeUnknown rather than a guess.
func cpeProductVersion(cpe string) (product, version string) {
	// Lowercased whole: CPE components are case-insensitive by spec, and vendors are
	// inconsistent about the `cpe:` prefix itself, so a case-sensitive prefix test would reject
	// a perfectly valid identifier.
	c := strings.ToLower(strings.TrimSpace(cpe))
	switch {
	case strings.HasPrefix(c, "cpe:2.3:"):
		// cpe:2.3:<part>:<vendor>:<product>:<version>:…
		f := splitEscaped(c[len("cpe:2.3:"):])
		if len(f) < 3 {
			return "", ""
		}
		if len(f) < 4 {
			return f[2], ""
		}
		return f[2], f[3]
	case strings.HasPrefix(c, "cpe:/"):
		// cpe:/<part>:<vendor>:<product>[:<version>]
		f := splitEscaped(c[len("cpe:/"):])
		if len(f) < 3 {
			return "", ""
		}
		if len(f) < 4 {
			return f[2], ""
		}
		return f[2], f[3]
	}
	return "", ""
}

// splitEscaped splits on ':' honouring backslash escapes, so an escaped colon inside a component
// does not create a field. The same rule the NVD CPE reader needs (KN-CLAIM-1's `splitCPE`).
func splitEscaped(s string) []string {
	var (
		out []string
		cur strings.Builder
		esc bool
	)
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

// ScopeFromCPE classifies a vendor CPE into a product scope (D5).
//
// It classifies the PRODUCT first and only then keeps the version, so a non-OS product can never
// have its version mistaken for an operating-system major:
//
//	cpe:/o:redhat:enterprise_linux:8        → enterprise-linux / 8
//	cpe:/a:redhat:openshift_pipelines:1     → openshift_pipelines / 1   (known, different)
//	cpe:/a:redhat:rhel_software_collections → openshift-style product with NO version → unknown
//	missing / malformed                     → unknown
//
// A product with no version yields an unestablished scope rather than a family-only one: "which
// major of it" is part of the question, and answering half of it is not an answer.
func ScopeFromCPE(cpe string) ProductScope {
	product, version := cpeProductVersion(cpe)
	product, version = strings.ToLower(strings.TrimSpace(product)), strings.TrimSpace(version)
	if product == "" || version == "" || version == "*" || version == "-" {
		return ProductScope{}
	}
	family := product
	if product == "enterprise_linux" {
		family = FamilyEnterpriseLinux
	}
	// Only the MAJOR is retained: a vendor states a product major, and a release's `elN` marker
	// carries the same granularity. Keeping a minor would make `8` and `8.10` disagree.
	if i := strings.IndexByte(version, '.'); i > 0 {
		version = version[:i]
	}
	return ProductScope{Family: family, Major: version}
}

// ScopeFromRPMRelease derives a release's own scope from an installed rpm build.
//
// The `elN` marker IS the family+major statement: an `elN`-tagged build belongs to the
// RHEL-compatible family at major N, whether it came from RHEL, Rocky or Alma. That is what makes
// a `Red Hat Enterprise Linux 8` statement cover a `Rocky Linux 8.10` release without any
// product-string comparison (D6).
//
// No resolvable marker → an unestablished scope, so applicability is `unknown` rather than a
// guess — the fail-safe direction, since an unknown scope cannot suppress anything.
func ScopeFromRPMRelease(installedVersion string) ProductScope {
	major := RPMReleaseMajor(installedVersion)
	if major == "" {
		return ProductScope{}
	}
	return ProductScope{Family: FamilyEnterpriseLinux, Major: major}
}
