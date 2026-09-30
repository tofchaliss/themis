package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/platform/auth"
)

func TestParseScopes(t *testing.T) {
	got := parseScopes(" admin , product:prod-1 ,, delivery:callback ")
	want := []string{auth.ScopeAdmin, auth.ProductScopePrefix + "prod-1", auth.ScopeDeliveryCallback}
	if len(got) != len(want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("scope[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// An empty --scopes mints a key with no grant at all, not a nil slice.
	if s := parseScopes(""); len(s) != 0 || s == nil {
		t.Errorf("empty scopes = %v, want an empty non-nil slice", s)
	}
}

// Minting is the only place the closed vocabulary can be enforced: a stored scope is read by
// every node afterwards (EDR-DELIVERY-01 N-M0).
func TestValidScopes(t *testing.T) {
	ok := []string{auth.ScopeAdmin, auth.ScopeRead,
		auth.ProductScopePrefix + "9c8f1a2e-0000-4000-8000-000000000001", auth.ScopeDeliveryCallback}
	got, err := validScopes(ok)
	if err != nil {
		t.Fatalf("validScopes(%v): %v", ok, err)
	}
	if len(got) != len(ok) {
		t.Errorf("valid scopes must pass through unchanged: %v", got)
	}

	for _, bad := range []string{"write", "produc:prod-1", auth.ProductScopePrefix, "delivery:webhook"} {
		if _, err := validScopes([]string{auth.ScopeRead, bad}); err == nil {
			t.Errorf("validScopes accepted %q — the vocabulary is closed", bad)
		} else if !strings.Contains(err.Error(), bad) {
			t.Errorf("the error must name the offending scope, got %v", err)
		}
	}
}

// The help text is the operator's only reference for what may be minted, so the two scopes this
// change concerns must appear in it.
func TestUsageDocumentsTheScopeVocabulary(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	usage()
	_ = w.Close()
	os.Stderr = orig

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	for _, want := range []string{auth.ScopeDeliveryCallback, auth.ProductScopePrefix + "<id>", auth.ScopeAdmin, auth.ScopeRead} {
		if !strings.Contains(text, want) {
			t.Errorf("usage does not mention %q:\n%s", want, text)
		}
	}
}
