// Package session is the dashboard's authenticated browser edge (EDR-GUI-01 D2/D3/D12):
// an operator pastes their API key once into the login form, the key is verified against
// the shared auth store, and a server-side session takes over — the browser holds only a
// random HttpOnly cookie, never a credential.
//
// It is deliberately DASHBOARD-LOCAL (D12): browser sessions are a concern no other node
// has, and growing the shared `internal/platform/auth` package for one consumer is how
// platform packages rot. This package *uses* platform/auth (the key store and the
// Principal vocabulary); it adds nothing to it.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

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

// entry is one live session. rawKey is retained IN SERVER MEMORY ONLY so mutations can
// re-verify the key is still active (D12) — it is never persisted and never re-sent; the
// browser holds only the random token.
type entry struct {
	principal auth.Principal
	rawKey    string
	lastSeen  time.Time
}

// Manager owns the in-memory session table. In-memory on purpose (D12): a dashboard
// restart logs everyone out, which for a small set of named operators is a feature — no
// session outlives the process that minted it.
type Manager struct {
	verifier Verifier
	idle     time.Duration
	now      func() time.Time

	mu       sync.Mutex
	sessions map[string]*entry
}

// NewManager builds a Manager. idle <= 0 selects DefaultIdleExpiry; now nil selects
// time.Now (injectable so expiry is testable without sleeping).
func NewManager(v Verifier, idle time.Duration, now func() time.Time) *Manager {
	if idle <= 0 {
		idle = DefaultIdleExpiry
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{verifier: v, idle: idle, now: now, sessions: map[string]*entry{}}
}

// Login verifies the pasted key and mints a session, returning the opaque token for the
// cookie. The one moment the raw key is handled; from here on the token stands in for it.
func (m *Manager) Login(ctx context.Context, rawKey string) (string, auth.Principal, bool) {
	p, ok := m.verifier.Verify(ctx, rawKey)
	if !ok {
		return "", auth.Principal{}, false
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", auth.Principal{}, false
	}
	token := hex.EncodeToString(buf)
	m.mu.Lock()
	m.sessions[token] = &entry{principal: p, rawKey: rawKey, lastSeen: m.now()}
	m.mu.Unlock()
	return token, p, true
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

// Reverify is the mutation-path check (D12): the session's key must STILL be active. A
// revoked operator can read until their session expires but can decide nothing from the
// moment of revocation — the damage-bounding check sits on the write path, the same
// fail-safe direction as the rest of Themis. On success the principal is refreshed (a
// scope change takes effect immediately); on failure the session is killed outright.
func (m *Manager) Reverify(ctx context.Context, token string) (auth.Principal, bool) {
	m.mu.Lock()
	e, ok := m.sessions[token]
	m.mu.Unlock()
	if !ok {
		return auth.Principal{}, false
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

// Logout removes the session; the cookie it served is thereafter just a random number.
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}
