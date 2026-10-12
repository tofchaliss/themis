package session_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/dashboard/session"
	"github.com/themis-project/themis/internal/dashboard/userstore"
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

// fakeUsers is an in-memory stand-in for the dashboard_users table. `err` forces every read
// to fail, which is how the "table was never migrated" and "database is down" paths are
// exercised without a database.
type fakeUsers struct {
	mu    sync.Mutex
	rows  map[string]userstore.User
	err   error
	clock time.Time
}

func newFakeUsers(t *testing.T, username, password string, isDefault bool) *fakeUsers {
	t.Helper()
	return &fakeUsers{
		rows: map[string]userstore.User{
			username: {
				Username:          username,
				PasswordHash:      hashFor(t, password),
				IsDefaultPassword: isDefault,
				UpdatedAt:         time.Unix(1_700_000_000, 0).UTC(),
			},
		},
		clock: time.Unix(1_700_000_000, 0).UTC(),
	}
}

// hashFor uses MinCost: a test is not a security boundary, and DefaultCost here would add
// ~100 ms per login to a package that logs in dozens of times.
func hashFor(t *testing.T, password string) []byte {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash %q: %v", password, err)
	}
	return h
}

func (f *fakeUsers) GetUser(_ context.Context, username string) (userstore.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return userstore.User{}, f.err
	}
	u, ok := f.rows[username]
	if !ok {
		return userstore.User{}, userstore.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) UpdatePassword(_ context.Context, username string, hash []byte) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return time.Time{}, f.err
	}
	u, ok := f.rows[username]
	if !ok {
		return time.Time{}, userstore.ErrNotFound
	}
	f.clock = f.clock.Add(time.Second) // the real column is bumped by now()
	u.PasswordHash = hash
	u.IsDefaultPassword = false
	u.UpdatedAt = f.clock
	f.rows[username] = u
	return u.UpdatedAt, nil
}

// bump models an out-of-band password change (another session, or psql).
func (f *fakeUsers) bump(username string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.rows[username]
	f.clock = f.clock.Add(time.Second)
	u.UpdatedAt = f.clock
	f.rows[username] = u
}

var alice = auth.Principal{KeyID: "k-1", Name: "alice", Scopes: []string{"admin"}}

func TestManager_LoginAndPrincipal(t *testing.T) {
	v := &fakeVerifier{valid: map[string]auth.Principal{"good-key": alice}}
	m := session.NewManager(v, nil, 0, nil)

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
	m := session.NewManager(v, nil, 8*time.Hour, clock)

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
	m := session.NewManager(v, nil, 0, nil)
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
	m := session.NewManager(v, nil, 0, nil)
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
	m := session.NewManager(v, nil, 0, nil)
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

/* ---------- password sign-in (EDR-GUI-01 D3 amendment 2026-10-12) ---------- */

// passwordManager wires a Manager with both doors open: the key verifier knows alice's key,
// the directory knows the admin account.
func passwordManager(t *testing.T, password string, isDefault bool) (*session.Manager, *fakeUsers) {
	t.Helper()
	users := newFakeUsers(t, userstore.AdminUsername, password, isDefault)
	v := &fakeVerifier{valid: map[string]auth.Principal{"good-key": alice}}
	return session.NewManager(v, users, 0, nil), users
}

// A password login mints the SAME kind of session a key login does, with the USERNAME as the
// principal id — which is what D13's identity check and every stamped actor_id read.
func TestManager_LoginPassword(t *testing.T) {
	m, _ := passwordManager(t, "Themis@123", true)
	ctx := context.Background()

	token, p, ok := m.LoginPassword(ctx, "admin", "Themis@123")
	if !ok {
		t.Fatal("the correct password was refused")
	}
	if p.Name != "admin" || p.KeyID != "admin" || !p.IsAdmin() {
		t.Errorf("principal = %+v, want the admin-scoped `admin` operator", p)
	}
	if got, ok := m.Principal(token); !ok || got.Name != "admin" {
		t.Errorf("Principal(token) = (%+v, %v), want the admin session", got, ok)
	}
}

// Every failure is the same undiagnosed "no" — a login form must not say which half was
// wrong, and must not distinguish "never migrated" from "wrong password".
func TestManager_LoginPasswordRefusals(t *testing.T) {
	ctx := context.Background()
	m, users := passwordManager(t, "Themis@123", true)

	cases := []struct{ name, user, pass string }{
		{"wrong password", "admin", "nope"},
		{"unknown user", "mallory", "Themis@123"},
		{"empty username", "", "Themis@123"},
		{"empty password", "admin", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := m.LoginPassword(ctx, tc.user, tc.pass); ok {
				t.Error("the attempt was accepted")
			}
		})
	}

	// The table was never created (THEMIS_DASHBOARD_MIGRATE not set): password sign-in
	// fails exactly like a wrong password, and the key door is untouched.
	t.Run("missing table fails like a wrong password", func(t *testing.T) {
		users.err = userstore.ErrTableMissing
		if _, _, ok := m.LoginPassword(ctx, "admin", "Themis@123"); ok {
			t.Error("a login succeeded against a missing table")
		}
		if _, _, ok := m.Login(ctx, "good-key"); !ok {
			t.Error("API-key sign-in must keep working when the password table is absent")
		}
	})

	// No directory at all (auth on, password login not wired) is the same answer.
	t.Run("no directory", func(t *testing.T) {
		keyOnly := session.NewManager(&fakeVerifier{valid: map[string]auth.Principal{}}, nil, 0, nil)
		if _, _, ok := keyOnly.LoginPassword(ctx, "admin", "Themis@123"); ok {
			t.Error("a login succeeded with no directory wired")
		}
	})
}

// The happy path: the password changes, the flag clears, the session is reissued under a new
// token, and the OLD token is dead.
func TestManager_ChangePassword(t *testing.T) {
	m, users := passwordManager(t, "Themis@123", true)
	ctx := context.Background()
	old, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")

	fresh, err := m.ChangePassword(ctx, old, "Themis@123", "quiet-mountain")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if fresh == old || fresh == "" {
		t.Fatalf("token = %q, want a reissued token", fresh)
	}
	if _, ok := m.Principal(old); ok {
		t.Error("the pre-change token still resolves — the session must be reissued")
	}
	if p, ok := m.Principal(fresh); !ok || p.Name != "admin" {
		t.Errorf("reissued session = (%+v, %v), want the same operator", p, ok)
	}
	// The reissued session must still be able to WRITE: an operator logged out by their own
	// password change would have to sign in again to do the thing they came to do.
	if _, ok := m.Reverify(ctx, fresh); !ok {
		t.Error("the reissued session failed the mutation re-verify")
	}
	u, _ := users.GetUser(ctx, "admin")
	if u.IsDefaultPassword {
		t.Error("is_default_password survived a password change")
	}
	if _, _, ok := m.LoginPassword(ctx, "admin", "quiet-mountain"); !ok {
		t.Error("the new password does not work")
	}
	if _, _, ok := m.LoginPassword(ctx, "admin", "Themis@123"); ok {
		t.Error("the old password still works")
	}
}

func TestManager_ChangePasswordRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("wrong current", func(t *testing.T) {
		m, _ := passwordManager(t, "Themis@123", true)
		token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
		if _, err := m.ChangePassword(ctx, token, "not-it", "whatever"); !errors.Is(err, session.ErrWrongPassword) {
			t.Errorf("err = %v, want ErrWrongPassword", err)
		}
	})

	// The ONLY rule on a new password (owner decision: no complexity requirements).
	t.Run("empty new", func(t *testing.T) {
		m, _ := passwordManager(t, "Themis@123", true)
		token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
		if _, err := m.ChangePassword(ctx, token, "Themis@123", ""); !errors.Is(err, session.ErrEmptyPassword) {
			t.Errorf("err = %v, want ErrEmptyPassword", err)
		}
	})

	// A one-character password is accepted: there are deliberately no complexity rules.
	t.Run("a short password is allowed", func(t *testing.T) {
		m, _ := passwordManager(t, "Themis@123", true)
		token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
		if _, err := m.ChangePassword(ctx, token, "Themis@123", "x"); err != nil {
			t.Errorf("err = %v, want a short password to be accepted", err)
		}
	})

	t.Run("a key session has no GUI password", func(t *testing.T) {
		m, _ := passwordManager(t, "Themis@123", true)
		token, _, _ := m.Login(ctx, "good-key")
		if _, err := m.ChangePassword(ctx, token, "Themis@123", "new"); !errors.Is(err, session.ErrNoPasswordSession) {
			t.Errorf("err = %v, want ErrNoPasswordSession", err)
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		m, _ := passwordManager(t, "Themis@123", true)
		if _, err := m.ChangePassword(ctx, "not-a-token", "Themis@123", "new"); !errors.Is(err, session.ErrNoPasswordSession) {
			t.Errorf("err = %v, want ErrNoPasswordSession", err)
		}
	})

	t.Run("store unavailable is NOT reported as a wrong password", func(t *testing.T) {
		m, users := passwordManager(t, "Themis@123", true)
		token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
		users.err = userstore.ErrTableMissing
		if _, err := m.ChangePassword(ctx, token, "Themis@123", "new"); !errors.Is(err, session.ErrPasswordsUnavailable) {
			t.Errorf("err = %v, want ErrPasswordsUnavailable — an operator told `wrong password` "+
				"when the table was never created would never find the migration flag", err)
		}
	})

	t.Run("the row vanished under the session", func(t *testing.T) {
		m, users := passwordManager(t, "Themis@123", true)
		token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
		delete(users.rows, "admin")
		if _, err := m.ChangePassword(ctx, token, "Themis@123", "new"); !errors.Is(err, session.ErrNoPasswordSession) {
			t.Errorf("err = %v, want ErrNoPasswordSession", err)
		}
	})

	t.Run("no directory wired", func(t *testing.T) {
		m, _ := passwordManager(t, "Themis@123", true)
		token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
		keyOnly := session.NewManager(&fakeVerifier{}, nil, 0, nil)
		if _, err := keyOnly.ChangePassword(ctx, token, "Themis@123", "new"); !errors.Is(err, session.ErrNoPasswordSession) {
			t.Errorf("err = %v, want ErrNoPasswordSession (the token is not in this manager)", err)
		}
	})
}

// The point of the stamp: a password change ends the user's OTHER sessions. Two browsers are
// signed in as admin; one changes the password; the other can no longer decide anything.
func TestManager_ChangePasswordEndsOtherSessions(t *testing.T) {
	m, _ := passwordManager(t, "Themis@123", true)
	ctx := context.Background()
	elsewhere, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
	here, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")

	if _, ok := m.Reverify(ctx, elsewhere); !ok {
		t.Fatal("the second session could not write before the change")
	}
	if _, err := m.ChangePassword(ctx, here, "Themis@123", "quiet-mountain"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if _, ok := m.Principal(elsewhere); ok {
		t.Error("the other session survived the password change")
	}
	if _, ok := m.Reverify(ctx, elsewhere); ok {
		t.Error("the other session could still write after the password change")
	}
}

// The D12 password half, on its own: a stamp that no longer matches the row refuses the
// write and kills the session — this is what the proxy Gate calls on every mutation.
func TestManager_ReverifyRefusesAChangedPassword(t *testing.T) {
	m, users := passwordManager(t, "Themis@123", true)
	ctx := context.Background()
	token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")

	if _, ok := m.Reverify(ctx, token); !ok {
		t.Fatal("re-verify failed on an unchanged password")
	}
	users.bump("admin") // somebody changed it out of band
	if _, ok := m.Reverify(ctx, token); ok {
		t.Fatal("re-verify passed a session whose password changed since login")
	}
	if _, ok := m.Principal(token); ok {
		t.Error("the session survived a failed re-verify — it must be killed outright")
	}
}

// A store that cannot answer refuses the write, in the same fail-safe direction the key path
// takes: never forward a mutation on the strength of a session nobody could confirm.
func TestManager_ReverifyRefusesWhenTheStoreIsUnreadable(t *testing.T) {
	m, users := passwordManager(t, "Themis@123", true)
	ctx := context.Background()
	token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
	users.err = errors.New("db down")
	if _, ok := m.Reverify(ctx, token); ok {
		t.Fatal("re-verify passed while the store was unreadable")
	}
}

func TestManager_InvalidateUser(t *testing.T) {
	m, _ := passwordManager(t, "Themis@123", true)
	ctx := context.Background()
	a, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
	b, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
	key, _, _ := m.Login(ctx, "good-key")

	if n := m.InvalidateUser("admin", a); n != 1 {
		t.Errorf("dropped %d, want 1 (the other admin session)", n)
	}
	if _, ok := m.Principal(b); ok {
		t.Error("session b survived")
	}
	if _, ok := m.Principal(a); !ok {
		t.Error("the kept session was dropped")
	}
	if _, ok := m.Principal(key); !ok {
		t.Error("a KEY session was dropped by a username invalidation")
	}
	if n := m.InvalidateUser("admin", ""); n != 1 {
		t.Errorf("dropped %d, want 1 — an empty keep-token drops them all", n)
	}
}

// The notice the GUI shows: a property of the deployment, not of the asking session.
func TestManager_DefaultPasswordInUse(t *testing.T) {
	ctx := context.Background()

	m, users := passwordManager(t, "Themis@123", true)
	if used, err := m.DefaultPasswordInUse(ctx); err != nil || !used {
		t.Errorf("fresh deployment = (%v, %v), want true", used, err)
	}
	token, _, _ := m.LoginPassword(ctx, "admin", "Themis@123")
	if _, err := m.ChangePassword(ctx, token, "Themis@123", "quiet-mountain"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if used, err := m.DefaultPasswordInUse(ctx); err != nil || used {
		t.Errorf("after the change = (%v, %v), want false", used, err)
	}

	delete(users.rows, "admin")
	if used, err := m.DefaultPasswordInUse(ctx); err != nil || used {
		t.Errorf("no admin row = (%v, %v), want (false, nil)", used, err)
	}
	users.err = userstore.ErrTableMissing
	if _, err := m.DefaultPasswordInUse(ctx); !errors.Is(err, session.ErrPasswordsUnavailable) {
		t.Errorf("missing table err = %v, want ErrPasswordsUnavailable", err)
	}
	keyOnly := session.NewManager(&fakeVerifier{}, nil, 0, nil)
	if _, err := keyOnly.DefaultPasswordInUse(ctx); !errors.Is(err, session.ErrPasswordsUnavailable) {
		t.Errorf("no directory err = %v, want ErrPasswordsUnavailable", err)
	}
}
