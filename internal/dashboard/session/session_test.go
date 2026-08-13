package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/dashboard/session"
	"github.com/themis-project/themis/internal/platform/auth"
)

// fakeVerifier scripts key validity per raw key, and can be flipped mid-test to model a
// revocation between login and a later write.
type fakeVerifier struct {
	valid map[string]auth.Principal
}

func (f *fakeVerifier) Verify(_ context.Context, raw string) (auth.Principal, bool) {
	p, ok := f.valid[raw]
	return p, ok
}

var alice = auth.Principal{KeyID: "k-1", Name: "alice", Scopes: []string{"admin"}}

func TestManager_LoginAndPrincipal(t *testing.T) {
	v := &fakeVerifier{valid: map[string]auth.Principal{"good-key": alice}}
	m := session.NewManager(v, 0, nil)

	if _, _, ok := m.Login(context.Background(), "wrong-key"); ok {
		t.Fatal("an invalid key must not mint a session")
	}
	token, p, ok := m.Login(context.Background(), "good-key")
	if !ok || p.Name != "alice" || token == "" {
		t.Fatalf("login = (%q, %+v, %v), want a token for alice", token, p, ok)
	}
	if got, ok := m.Principal(token); !ok || got.Name != "alice" {
		t.Errorf("Principal(token) = (%+v, %v), want alice", got, ok)
	}
	if _, ok := m.Principal("not-a-token"); ok {
		t.Error("an unknown token resolved to a session")
	}
}

// Idle expiry (D12): a session untouched past the idle window is gone — verified with an
// injected clock, because a test that sleeps 8 hours is a test nobody runs.
func TestManager_IdleExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	v := &fakeVerifier{valid: map[string]auth.Principal{"good-key": alice}}
	m := session.NewManager(v, 8*time.Hour, clock)

	token, _, _ := m.Login(context.Background(), "good-key")
	now = now.Add(7 * time.Hour)
	if _, ok := m.Principal(token); !ok {
		t.Fatal("7h idle expired a session with an 8h window")
	}
	// The 7h touch refreshed the clock; 9h more crosses the window.
	now = now.Add(9 * time.Hour)
	if _, ok := m.Principal(token); ok {
		t.Fatal("9h idle survived an 8h window")
	}
}

// The D12 core: revocation bites on the next WRITE, not at the next login. The verifier
// flips mid-session (authadmin revoke-key), Reverify kills the session outright.
func TestManager_ReverifyKillsRevokedSession(t *testing.T) {
	v := &fakeVerifier{valid: map[string]auth.Principal{"good-key": alice}}
	m := session.NewManager(v, 0, nil)
	token, _, _ := m.Login(context.Background(), "good-key")

	if _, ok := m.Reverify(context.Background(), token); !ok {
		t.Fatal("Reverify failed while the key was still active")
	}
	delete(v.valid, "good-key") // the revocation
	if _, ok := m.Reverify(context.Background(), token); ok {
		t.Fatal("Reverify passed a revoked key")
	}
	if _, ok := m.Principal(token); ok {
		t.Fatal("the session survived a failed Reverify — it must be killed outright")
	}
	if _, ok := m.Reverify(context.Background(), "not-a-token"); ok {
		t.Error("Reverify accepted an unknown token")
	}
}

// A scope change (not a revocation) takes effect at the next write: Reverify refreshes
// the principal rather than serving login-time scopes forever.
func TestManager_ReverifyRefreshesScopes(t *testing.T) {
	v := &fakeVerifier{valid: map[string]auth.Principal{"good-key": alice}}
	m := session.NewManager(v, 0, nil)
	token, _, _ := m.Login(context.Background(), "good-key")

	demoted := alice
	demoted.Scopes = []string{"read"}
	v.valid["good-key"] = demoted

	p, ok := m.Reverify(context.Background(), token)
	if !ok || p.AuthorizeWrite() {
		t.Fatalf("Reverify = (%+v, %v), want the demoted read-only principal", p, ok)
	}
	if got, _ := m.Principal(token); got.AuthorizeWrite() {
		t.Error("the session kept its login-time scopes after Reverify saw the demotion")
	}
}

func TestManager_Logout(t *testing.T) {
	v := &fakeVerifier{valid: map[string]auth.Principal{"good-key": alice}}
	m := session.NewManager(v, 0, nil)
	token, _, _ := m.Login(context.Background(), "good-key")
	m.Logout(token)
	if _, ok := m.Principal(token); ok {
		t.Fatal("a logged-out token still resolved")
	}
}

// KeyVerifier mirrors the platform middleware's semantics: bcrypt match + expiry check,
// and every failure — store error, no match, expired — is the same undiagnosed "invalid".
func TestKeyVerifier(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	keys := []auth.APIKey{
		{ID: "k-1", Name: "alice", KeyHash: "hash-alice", Scopes: []string{"admin"}},
		{ID: "k-2", Name: "bob", KeyHash: "hash-bob", Scopes: []string{"read"}, ExpiresAt: &past},
		{ID: "k-3", Name: "carol", KeyHash: "hash-carol", Scopes: []string{"read"}, ExpiresAt: &future},
	}
	v := session.KeyVerifier{
		Keys: stubKeys{keys: keys},
		Now:  func() time.Time { return now },
		Compare: func(hash, raw []byte) error {
			if string(hash) == "hash-"+string(raw) {
				return nil
			}
			return errors.New("mismatch")
		},
	}
	ctx := context.Background()
	if p, ok := v.Verify(ctx, "alice"); !ok || p.Name != "alice" || !p.IsAdmin() {
		t.Errorf("alice = (%+v, %v), want the admin principal", p, ok)
	}
	if _, ok := v.Verify(ctx, "bob"); ok {
		t.Error("an expired key verified")
	}
	if p, ok := v.Verify(ctx, "carol"); !ok || p.Name != "carol" {
		t.Errorf("carol = (%+v, %v), want valid — expiry is in the future", p, ok)
	}
	if _, ok := v.Verify(ctx, "nobody"); ok {
		t.Error("an unknown key verified")
	}
	if _, ok := (session.KeyVerifier{Keys: stubKeys{err: errors.New("db down")}}).Verify(ctx, "alice"); ok {
		t.Error("a store error verified a key")
	}
}

type stubKeys struct {
	keys []auth.APIKey
	err  error
}

func (s stubKeys) ActiveKeys(context.Context) ([]auth.APIKey, error) { return s.keys, s.err }
