package auth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPrincipalScopes(t *testing.T) {
	tests := []struct {
		name        string
		scopes      []string
		wantAdmin   bool
		scopeReq    string
		wantScope   bool
		productID   string
		wantProduct bool
		wantWrite   bool
	}{
		{"admin grants everything", []string{ScopeAdmin}, true, "anything", true, "p1", true, true},
		{"read only", []string{ScopeRead}, false, ScopeRead, true, "p1", false, false},
		{"read denied other scope", []string{ScopeRead}, false, "admin", false, "p1", false, false},
		{"product scoped", []string{ProductScopePrefix + "p1"}, false, ProductScopePrefix + "p1", true, "p1", true, true},
		{"product scoped wrong product", []string{ProductScopePrefix + "p1"}, false, "x", false, "p2", false, true},
		{"empty scopes", nil, false, "read", false, "p1", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Principal{KeyID: "k", Scopes: tt.scopes}
			if got := p.IsAdmin(); got != tt.wantAdmin {
				t.Errorf("IsAdmin() = %v, want %v", got, tt.wantAdmin)
			}
			if got := p.AuthorizeScope(tt.scopeReq); got != tt.wantScope {
				t.Errorf("AuthorizeScope(%q) = %v, want %v", tt.scopeReq, got, tt.wantScope)
			}
			if got := p.AuthorizeProduct(tt.productID); got != tt.wantProduct {
				t.Errorf("AuthorizeProduct(%q) = %v, want %v", tt.productID, got, tt.wantProduct)
			}
			if got := p.AuthorizeWrite(); got != tt.wantWrite {
				t.Errorf("AuthorizeWrite() = %v, want %v", got, tt.wantWrite)
			}
		})
	}
}

// The explicit-scope helpers behind Governance's write gate (EDR-DELIVERY-01 N-M0). They differ
// from AuthorizeScope/AuthorizeProduct in one deliberate way: admin implies NOTHING here, so the
// admin branch stays visible at the decision site instead of hiding inside a helper.
func TestPrincipalExplicitScopeHelpers(t *testing.T) {
	admin := Principal{Scopes: []string{ScopeAdmin}}
	product := Principal{Scopes: []string{ProductScopePrefix + "prod-1"}}
	callback := Principal{Scopes: []string{ScopeDeliveryCallback}}
	both := Principal{Scopes: []string{ScopeAdmin, ScopeDeliveryCallback}}

	if admin.HasScopeExact(ProductScopePrefix + "prod-1") {
		t.Error("HasScopeExact must not fold in admin — that is AuthorizeScope's job")
	}
	if !product.HasScopeExact(ProductScopePrefix + "prod-1") {
		t.Error("HasScopeExact missed the exact grant")
	}
	if product.HasScope(ProductScopePrefix+"prod-1") != product.HasScopeExact(ProductScopePrefix+"prod-1") {
		t.Error("HasScope and HasScopeExact must be one implementation")
	}

	if !product.HasScopePrefix(ProductScopePrefix) {
		t.Error("a product-scoped key must match the product prefix")
	}
	if admin.HasScopePrefix(ProductScopePrefix) {
		t.Error("admin carries no product grant")
	}
	// The bare prefix is not a grant: "product:" with no id must not read as product-scoped.
	if (Principal{Scopes: []string{ProductScopePrefix}}).HasScopePrefix(ProductScopePrefix) {
		t.Error("a bare prefix with no product id is not a product grant")
	}

	if !product.HasProductScope("prod-1") {
		t.Error("HasProductScope missed its own product")
	}
	if product.HasProductScope("prod-2") {
		t.Error("HasProductScope must not match another product")
	}
	if product.HasProductScope("") {
		t.Error("an unresolved (blank) product must never match — fail closed")
	}
	if admin.HasProductScope("prod-1") {
		t.Error("HasProductScope must not fold in admin")
	}

	if !callback.IsDeliveryCallback() || !both.IsDeliveryCallback() {
		t.Error("the callback scope must be visible however it was minted, admin beside it or not")
	}
	if product.IsDeliveryCallback() {
		t.Error("a product key is not a callback key")
	}
	// The method-based floor: a callback credential is not write-capable in ANY context, so
	// minting the scope cannot hand mutating access to Knowledge/Evidence/Communication.
	if callback.AuthorizeWrite() {
		t.Error("delivery:callback must not satisfy AuthorizeWrite")
	}
	if !product.AuthorizeWrite() || !admin.AuthorizeWrite() {
		t.Error("the existing write tiers must be unchanged")
	}
}

// The vocabulary is closed, and this is the list. Before it was, any string at all could be
// stored as a scope — and AuthorizeWrite granted write to every one of them that was not `read`.
func TestKnownScope(t *testing.T) {
	for _, s := range []string{ScopeAdmin, ScopeRead, ScopeDeliveryCallback, ProductScopePrefix + "prod-1"} {
		if !KnownScope(s) {
			t.Errorf("KnownScope(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", " ", "write", "produc:prod-1", ProductScopePrefix, "delivery:", "admin ", "governance:write"} {
		if KnownScope(s) {
			t.Errorf("KnownScope(%q) = true — the vocabulary is closed", s)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	raw, hash, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !strings.HasPrefix(raw, "thm_") {
		t.Errorf("raw token %q missing thm_ prefix", raw)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw)); err != nil {
		t.Errorf("hash does not verify against raw token: %v", err)
	}
	// Two mints differ (randomness).
	raw2, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (2): %v", err)
	}
	if raw == raw2 {
		t.Errorf("two generated tokens are identical: %q", raw)
	}
}
