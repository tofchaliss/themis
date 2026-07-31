package auth

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

// Scope tiers, ported verbatim from the v0.3.x monolith's authorization model (D4).
const (
	// ScopeAdmin grants global access to every endpoint.
	ScopeAdmin = "admin"
	// ScopeRead marks a key authenticated but restricted to non-mutating (read) endpoints.
	ScopeRead = "read"
	// ProductScopePrefix prefixes a product-scoped grant, e.g. "product:prod-123".
	ProductScopePrefix = "product:"
)

// Principal is the identity resolved from a valid API key and attached to the request
// context. It is plain data: the domain and app rings never import this type; adapters read
// it to authorize. KeyID is the auditable actor id (CON-0016 traceability).
type Principal struct {
	KeyID  string
	Name   string
	Scopes []string
}

// HasScope reports whether the principal was granted the exact scope.
func (p Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

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

// AuthorizeWrite reports whether the principal may perform a mutating operation: a read-only
// key (its only grant is ScopeRead) may not; admin and product-scoped keys may.
func (p Principal) AuthorizeWrite() bool {
	if p.IsAdmin() {
		return true
	}
	for _, s := range p.Scopes {
		if s != ScopeRead && s != "" {
			return true
		}
	}
	return false
}
