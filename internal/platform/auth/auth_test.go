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
