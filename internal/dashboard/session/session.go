// Package session is the dashboard's authenticated browser edge (EDR-GUI-01 D2/D3/D12):
// an operator signs in once — with a username and password, or by pasting their API key —
// and a server-side session takes over, so the browser holds only a random HttpOnly cookie,
// never a credential.
//
// It is deliberately DASHBOARD-LOCAL (D12): browser sessions are a concern no other node
// has, and growing the shared `internal/platform/auth` package for one consumer is how
// platform packages rot. This package *uses* platform/auth (the key store and the
// Principal vocabulary); it adds nothing to it — which is also why the password directory
// is the dashboard's own `internal/dashboard/userstore` and not a second platform table.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/dashboard/userstore"
	"github.com/themis-project/themis/internal/platform/auth"
)

// DefaultIdleExpiry is how long a session survives without a request (D12). Long enough
// for a working day with lunch, short enough that a forgotten workstation logs out.
const DefaultIdleExpiry = 8 * time.Hour

// Verifier resolves a raw API key to its Principal, or reports it invalid. Implemented by
// KeyVerifier against the auth store; injectable for tests.
type Verifier interface {
	Verify(ctx context.Context, rawKey string) (auth.Principal, bool)
}

// KeyVerifier verifies a presented key the same way the platform middleware does —
// bcrypt-compare against every active key, then check expiry. The loop is small enough
// that repeating it here beats exporting a helper from platform/auth (D12: the shared
// package stays per-request header verification and nothing more).
type KeyVerifier struct {
	Keys    auth.KeyStore
	Now     func() time.Time                            // nil = time.Now
	Compare func(hashedPassword, password []byte) error // nil = bcrypt.CompareHashAndPassword
}

// Verify resolves rawKey to its Principal. Any failure — store error, no match, expired —
// is simply "invalid": a login form needs no finer diagnosis, and finer diagnosis would
// leak which failure occurred.
func (v KeyVerifier) Verify(ctx context.Context, rawKey string) (auth.Principal, bool) {
	now := v.Now
	if now == nil {
		now = time.Now
	}
	compare := v.Compare
	if compare == nil {
		compare = bcrypt.CompareHashAndPassword
	}
	keys, err := v.Keys.ActiveKeys(ctx)
	if err != nil {
		return auth.Principal{}, false
	}
	for _, key := range keys {
		if compare([]byte(key.KeyHash), []byte(rawKey)) != nil {
			continue
		}
		if key.ExpiresAt != nil && !key.ExpiresAt.After(now()) {
			continue
		}
		return auth.Principal{KeyID: key.ID, Name: key.Name, Scopes: key.Scopes}, true
	}
	return auth.Principal{}, false
}

// Users is the dashboard-local login directory the password edge reads (implemented by
// userstore.Store). A nil Users means no password login exists — every password attempt
// then fails exactly like a wrong password, which is what a dashboard started against an
// un-migrated auth database must do (API-key login keeps working).
type Users interface {
	GetUser(ctx context.Context, username string) (userstore.User, error)
	UpdatePassword(ctx context.Context, username string, hash []byte) (time.Time, error)
}

// The refusals ChangePassword can state. Each maps to one HTTP answer at the edge, so the
// handler never has to guess which failure it is looking at.
var (
	// ErrNoPasswordSession — this session did not sign in with a password, so there is no
	// password of its own to change. An API-key operator rotates their key with authadmin.
	ErrNoPasswordSession = errors.New("session: not a password session")
	// ErrWrongPassword — the stated current password does not match the stored hash.
	ErrWrongPassword = errors.New("session: current password does not match")
	// ErrEmptyPassword — the new password is empty. The ONLY rule on a new password: there
	// are deliberately no complexity requirements (owner decision, EDR-GUI-01 D3 amendment).
	ErrEmptyPassword = errors.New("session: the new password is empty")
	// ErrPasswordsUnavailable — the dashboard_users table is absent or unreadable, so no
	// password can be verified or changed. Distinct from ErrWrongPassword on purpose: for a
	// LOGIN the two must be indistinguishable, but an operator told "wrong password" when the
	// table was never created would never find the migration flag.
	ErrPasswordsUnavailable = errors.New("session: the dashboard password store is unavailable")
)

// entry is one live session, in one of two kinds. A KEY session retains rawKey IN SERVER
// MEMORY ONLY so mutations can re-verify the key is still active (D12). A PASSWORD session
// retains the username and the `updated_at` stamp its row carried at login: the mutation
// re-verify compares the stamp, which is what makes a password change end the user's other
// sessions without any cross-session bookkeeping. Neither credential is ever persisted or
// re-sent; the browser holds only the random token.
type entry struct {
	principal auth.Principal
	rawKey    string // key sessions
	username  string // password sessions
	stamp     time.Time
	password  bool // true = password session, false = key session
	lastSeen  time.Time
}

// Manager owns the in-memory session table. In-memory on purpose (D12): a dashboard
// restart logs everyone out, which for a small set of named operators is a feature — no
// session outlives the process that minted it.
type Manager struct {
	verifier Verifier
	users    Users
	idle     time.Duration
	now      func() time.Time

	mu       sync.Mutex
	sessions map[string]*entry
}

// NewManager builds a Manager. users may be nil (no password login). idle <= 0 selects
// DefaultIdleExpiry; now nil selects time.Now (injectable so expiry is testable without
// sleeping).
func NewManager(v Verifier, users Users, idle time.Duration, now func() time.Time) *Manager {
	if idle <= 0 {
		idle = DefaultIdleExpiry
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{verifier: v, users: users, idle: idle, now: now, sessions: map[string]*entry{}}
}

// mintToken returns a fresh opaque session token.
func mintToken() (string, bool) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", false
	}
	return hex.EncodeToString(buf), true
}

// Login verifies the pasted key and mints a session, returning the opaque token for the
// cookie. The one moment the raw key is handled; from here on the token stands in for it.
func (m *Manager) Login(ctx context.Context, rawKey string) (string, auth.Principal, bool) {
	p, ok := m.verifier.Verify(ctx, rawKey)
	if !ok {
		return "", auth.Principal{}, false
	}
	token, ok := mintToken()
	if !ok {
		return "", auth.Principal{}, false
	}
	m.mu.Lock()
	m.sessions[token] = &entry{principal: p, rawKey: rawKey, lastSeen: m.now()}
	m.mu.Unlock()
	return token, p, true
}

// LoginPassword verifies a username and password against the dashboard's own directory and
// mints the SAME kind of server-side session a key login does (EDR-GUI-01 D3 amendment
// 2026-10-12). The principal's id is the USERNAME, so D13's identity check and every
// `actor_id` stamped on a decision read `admin` — the acknowledged cost of a shared account.
// The session carries admin scope: this account exists to administer the GUI.
//
// Every failure — unknown user, wrong password, missing table, store error — is the same
// undiagnosed "no": a login form needs no finer diagnosis, and finer diagnosis would leak
// which half was wrong.
func (m *Manager) LoginPassword(ctx context.Context, username, password string) (string, auth.Principal, bool) {
	if m.users == nil || username == "" || password == "" {
		return "", auth.Principal{}, false
	}
	u, err := m.users.GetUser(ctx, username)
	if err != nil {
		return "", auth.Principal{}, false
	}
	if bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)) != nil {
		return "", auth.Principal{}, false
	}
	token, ok := mintToken()
	if !ok {
		return "", auth.Principal{}, false
	}
	p := auth.Principal{KeyID: u.Username, Name: u.Username, Scopes: []string{auth.ScopeAdmin}}
	m.mu.Lock()
	m.sessions[token] = &entry{
		principal: p, username: u.Username, stamp: u.UpdatedAt, password: true, lastSeen: m.now(),
	}
	m.mu.Unlock()
	return token, p, true
}

// ChangePassword verifies the current password, stores a bcrypt hash of the new one, and
// returns the token the caller must re-cookie. Three things happen as one act:
//
//   - the row's `updated_at` is bumped, which invalidates every OTHER session of this user
//     through the D12 re-verify (an acceptance of a stolen cookie does not survive a
//     password change);
//   - this session is REISSUED under a fresh token carrying the new stamp, so the operator
//     who made the change is not logged out by their own action;
//   - the other sessions are dropped from the table outright, so they stop reading too
//     rather than lingering until idle expiry.
//
// There is deliberately no complexity rule: the only check is that the new password is not
// empty (the owner's decision — a rule nobody agreed to is a rule operators work around).
func (m *Manager) ChangePassword(ctx context.Context, token, current, next string) (string, error) {
	if next == "" {
		return "", ErrEmptyPassword
	}
	m.mu.Lock()
	e, ok := m.sessions[token]
	m.mu.Unlock()
	if !ok || !e.password {
		return "", ErrNoPasswordSession
	}
	if m.users == nil {
		return "", ErrPasswordsUnavailable
	}
	u, err := m.users.GetUser(ctx, e.username)
	if err != nil {
		if errors.Is(err, userstore.ErrNotFound) {
			return "", ErrNoPasswordSession // the row vanished under the session
		}
		return "", ErrPasswordsUnavailable
	}
	if bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(current)) != nil {
		return "", ErrWrongPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("session: hash the new password: %w", err)
	}
	stamp, err := m.users.UpdatePassword(ctx, e.username, hash)
	if err != nil {
		return "", ErrPasswordsUnavailable
	}
	fresh, ok := mintToken()
	if !ok {
		// The password IS changed; only the reissue failed. Dropping every session is the
		// fail-safe end: the operator signs in again with the new password.
		m.InvalidateUser(e.username, "")
		return "", fmt.Errorf("session: could not reissue the session after the password change")
	}
	m.mu.Lock()
	delete(m.sessions, token)
	m.sessions[fresh] = &entry{
		principal: e.principal, username: e.username, stamp: stamp, password: true, lastSeen: m.now(),
	}
	m.mu.Unlock()
	m.InvalidateUser(e.username, fresh)
	return fresh, nil
}

// InvalidateUser drops every password session of username except keepToken (pass "" to drop
// all of them) and reports how many it dropped. The table is scanned rather than indexed by
// username on purpose: it holds a handful of sessions, and an index would be a second
// structure to keep correct across expiry, logout and reissue.
func (m *Manager) InvalidateUser(username, keepToken string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	dropped := 0
	for token, e := range m.sessions {
		if e.password && e.username == username && token != keepToken {
			delete(m.sessions, token)
			dropped++
		}
	}
	return dropped
}

// DefaultPasswordInUse reports whether the seeded admin account still holds the shipped
// default password. It is a property of the DEPLOYMENT, not of the asking session, which is
// why the GUI shows the notice to every admin who signs in.
func (m *Manager) DefaultPasswordInUse(ctx context.Context) (bool, error) {
	if m.users == nil {
		return false, ErrPasswordsUnavailable
	}
	u, err := m.users.GetUser(ctx, userstore.AdminUsername)
	switch {
	case errors.Is(err, userstore.ErrNotFound):
		return false, nil
	case err != nil:
		return false, ErrPasswordsUnavailable
	}
	return u.IsDefaultPassword, nil
}

// Principal resolves a token to its operator, refreshing the idle clock. An expired or
// unknown token is simply not a session.
func (m *Manager) Principal(token string) (auth.Principal, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sessions[token]
	if !ok {
		return auth.Principal{}, false
	}
	now := m.now()
	if now.Sub(e.lastSeen) > m.idle {
		delete(m.sessions, token)
		return auth.Principal{}, false
	}
	e.lastSeen = now
	return e.principal, true
}

// Reverify is the mutation-path check (D12): the session's CREDENTIAL must still be good.
// For a key session that means the key is still active — a revoked operator can read until
// their session expires but can decide nothing from the moment of revocation, and on success
// the principal is refreshed so a scope change takes effect immediately. For a password
// session it means the user row still exists and its `updated_at` still equals the stamp
// captured at login — so a password change ends every other session's ability to decide.
// Either way the damage-bounding check sits on the write path, the same fail-safe direction
// as the rest of Themis, and a failure kills the session outright.
func (m *Manager) Reverify(ctx context.Context, token string) (auth.Principal, bool) {
	m.mu.Lock()
	e, ok := m.sessions[token]
	m.mu.Unlock()
	if !ok {
		return auth.Principal{}, false
	}
	if e.password {
		return m.reverifyPassword(ctx, token, e)
	}
	p, valid := m.verifier.Verify(ctx, e.rawKey)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !valid {
		delete(m.sessions, token)
		return auth.Principal{}, false
	}
	e.principal = p
	return p, true
}

// reverifyPassword is the password half of D12: the stamp comparison. A store error counts
// as a failure, in the same fail-safe direction the key path takes — a write is refused when
// the credential cannot be confirmed, never forwarded on the strength of a stale session.
func (m *Manager) reverifyPassword(ctx context.Context, token string, e *entry) (auth.Principal, bool) {
	current := false
	if m.users != nil {
		if u, err := m.users.GetUser(ctx, e.username); err == nil && u.UpdatedAt.Equal(e.stamp) {
			current = true
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !current {
		delete(m.sessions, token)
		return auth.Principal{}, false
	}
	return e.principal, true
}

// Logout removes the session; the cookie it served is thereafter just a random number.
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}
