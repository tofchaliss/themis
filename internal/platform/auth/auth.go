package auth

import "strings"

// Identity store schema — the single `api_keys` table in the shared `auth` database
// (EDR-SECURITY-01 D2). These names are the one source of truth shared by the Store and the
// migrations under ./migrations. The `auth` DB carries infrastructure identity, not business
// state, so it creates no cross-context business join (same justification as the `bus` DB).
const (
	TableAPIKeys = "api_keys"

	ColID        = "id"         // opaque key id (also the auditable principal id)
	ColName      = "name"       // human label for the key
	ColKeyHash   = "key_hash"   // bcrypt hash of the raw token; the token itself is never stored
	ColScopes    = "scopes"     // TEXT[] of granted scopes (D4)
	ColCreatedAt = "created_at" // issue time
	ColExpiresAt = "expires_at" // optional expiry; NULL = no expiry
	ColRevokedAt = "revoked_at" // set on revoke; NULL = active
)

// DefaultMigrationsPath is where the `auth` migrations live, applied against the `auth`
// database by a composition root (mirrors eventbus.DefaultMigrationsPath and each context's
// THEMIS_<CTX>_MIGRATIONS default; applied with golang-migrate over a file:// source).
const DefaultMigrationsPath = "internal/platform/auth/migrations"

// Scope tiers, ported verbatim from the v0.3.x monolith's authorization model (D4), plus the
// outward-actions callback scope (EDR-DELIVERY-01 N-M0). The vocabulary is CLOSED: KnownScope
// is the whole of it, and a scope outside it authorizes nothing.
const (
	// ScopeAdmin grants global access to every endpoint.
	ScopeAdmin = "admin"
	// ScopeRead marks a key authenticated but restricted to non-mutating (read) endpoints.
	ScopeRead = "read"
	// ProductScopePrefix prefixes a product-scoped grant, e.g. "product:prod-123".
	ProductScopePrefix = "product:"
	// ScopeDeliveryCallback is the credential class an outward delivery target calls BACK with
	// (EDR-DELIVERY-01 N-M0, runtime-side D-N-6). It is deliberately NOT write-capable: it
	// authorizes no Governance mutation whatever, because a callback reports on work Themis
	// asked for and must never be able to take a stance on a Finding.
	ScopeDeliveryCallback = "delivery:callback"
)

// KnownScope reports whether a scope string is part of the closed vocabulary: `admin`, `read`,
// `delivery:callback`, or `product:<non-empty-id>`. Minting is validated against this (cmd/
// authadmin) so an unknown scope cannot be stored and then silently read as authorization —
// before the vocabulary was closed, any non-`read` string at all satisfied AuthorizeWrite.
func KnownScope(scope string) bool {
	switch scope {
	case ScopeAdmin, ScopeRead, ScopeDeliveryCallback:
		return true
	}
	return strings.HasPrefix(scope, ProductScopePrefix) && len(scope) > len(ProductScopePrefix)
}

// Principal is the identity resolved from a valid API key and attached to the request
// context. It is plain data: the domain and app rings never import this type; adapters read
// it to authorize. KeyID is the auditable actor id (CON-0016 traceability).
type Principal struct {
	KeyID  string
	Name   string
	Scopes []string
}

// HasScopeExact reports whether the principal was granted this scope string verbatim. It
// implies nothing: `admin` does NOT satisfy it, which is what makes it usable as a building
// block for an explicit authorization rule (EDR-DELIVERY-01 N-M0) rather than a policy of its
// own. AuthorizeScope is the admin-implying form.
func (p Principal) HasScopeExact(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasScope is the original name for HasScopeExact, kept because callers across both trees use
// it; the two are one implementation, so they cannot drift.
func (p Principal) HasScope(scope string) bool { return p.HasScopeExact(scope) }

// HasScopePrefix reports whether the principal holds any scope with this prefix — the question
// "is this key product-scoped at all", asked separately from "is it scoped to THIS product", so
// a key that is neither admin nor product-scoped can be refused without a Registry read.
func (p Principal) HasScopePrefix(prefix string) bool {
	for _, s := range p.Scopes {
		if strings.HasPrefix(s, prefix) && len(s) > len(prefix) {
			return true
		}
	}
	return false
}

// HasProductScope reports whether the principal carries THIS product's grant. Unlike
// AuthorizeProduct it does not fold in admin: a caller that wants "admin or this product" says
// so, which keeps the admin branch visible at the decision site.
func (p Principal) HasProductScope(productID string) bool {
	if productID == "" {
		return false
	}
	return p.HasScopeExact(ProductScopePrefix + productID)
}

// IsDeliveryCallback reports whether the principal holds the outward-delivery callback scope.
// It is checked FIRST and refuses outright on Governance writes (EDR-DELIVERY-01 N-M0), so a
// key that also carries admin or a product grant is still refused — a credential handed to a
// delivery target must not be usable as a governance identity, however it was minted.
func (p Principal) IsDeliveryCallback() bool { return p.HasScopeExact(ScopeDeliveryCallback) }

// IsAdmin reports whether the principal holds the global admin scope.
func (p Principal) IsAdmin() bool { return p.HasScope(ScopeAdmin) }

// AuthorizeScope reports whether the principal satisfies a required scope: admin satisfies
// everything, otherwise the exact scope must be present. This is the check behind
// RequireScope middleware.
func (p Principal) AuthorizeScope(required string) bool {
	return p.IsAdmin() || p.HasScope(required)
}

// AuthorizeProduct reports whether the principal may act on the given product: admin, or a
// key carrying that product's scope (D4).
func (p Principal) AuthorizeProduct(productID string) bool {
	return p.IsAdmin() || p.HasScope(ProductScopePrefix+productID)
}

// AuthorizeWrite reports whether the principal may perform a mutating operation. Exactly two
// grants are write-capable, in every context: `admin`, and `product:<id>` for some id. Every
// other scope — `read`, `delivery:callback`, and anything outside the closed vocabulary — is
// not.
//
// It is the METHOD-based floor behind RequireWriteScope and stays exactly that. Governance no
// longer authorizes its writes with it (EDR-DELIVERY-01 N-M0/D1): this function cannot confine
// `product:<id>` to one product's Findings, because it sees a principal and no resource. The
// Governance handlers decide that explicitly; this floor sits below them, unchanged in role.
//
// WHAT CHANGED, AND WHY IT HAD TO. It used to grant write on the first scope that was not
// `read` or empty. So a typo (`produc:prod-1`), an invented grant (`governance:write`) and a
// scope minted for something else entirely were all indistinguishable from admin at any
// mutating endpoint in Knowledge, Evidence, Communication, Registry or Intelligence — a
// privilege escalation reachable by misspelling a flag. Closing the vocabulary (D5) is only a
// guarantee if the check that READS it is closed too; validating at mint time merely stops new
// ones being created. Operator consequence: a previously minted key whose scopes are outside the
// vocabulary loses write capability everywhere — see EDR-DELIVERY-01 D5 for the audit query.
func (p Principal) AuthorizeWrite() bool {
	return p.IsAdmin() || p.HasScopePrefix(ProductScopePrefix)
}
