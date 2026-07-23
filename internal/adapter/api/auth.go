package api

import (
	"context"
	"strings"

	"github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/domain"
)

// WithAuth stores the authenticated principal on the context.
func WithAuth(ctx context.Context, principal domain.AuthPrincipal) context.Context {
	return middleware.WithAuth(ctx, principal)
}

// AuthFromContext returns the authenticated principal.
func AuthFromContext(ctx context.Context) (domain.AuthPrincipal, bool) {
	return middleware.AuthFromContext(ctx)
}

// ClientIPFromContext returns the captured client IP, or "".
func ClientIPFromContext(ctx context.Context) string {
	return middleware.ClientIPFromContext(ctx)
}

// AuthorizeProduct returns false when the principal cannot access a product.
func AuthorizeProduct(principal domain.AuthPrincipal, productID string) bool {
	if hasScope(principal.Scopes, domain.ScopeAdmin) {
		return true
	}
	if productID == "" {
		return true
	}
	return hasScope(principal.Scopes, domain.ProductScopePrefix+productID)
}

// AuthorizeWriteConfig returns false for read-only keys.
func AuthorizeWriteConfig(principal domain.AuthPrincipal) bool {
	if hasScope(principal.Scopes, domain.ScopeAdmin) {
		return true
	}
	return !hasScope(principal.Scopes, domain.ScopeReadOnly)
}

func hasScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

// PageFromParams converts query params to a domain page request.
func PageFromParams(cursor *string, limit *int) domain.PageRequest {
	page := domain.PageRequest{Limit: 50}
	if cursor != nil {
		page.Cursor = strings.TrimSpace(*cursor)
	}
	if limit != nil && *limit > 0 {
		page.Limit = *limit
	}
	return page
}
