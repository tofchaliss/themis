package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/themis-project/themis/internal/platform/auth"
)

// Gate is the v1 scope-and-identity enforcement in front of the proxy (EDR-GUI-01
// D11/D13). It exists because D4 injects the ADMIN node key toward the nodes for every
// request — the nodes never see the operator's key until v2 pass-through — so the proxy
// is the only place that knows both WHO is asking (the session) and WHAT they ask (the
// route). Without this gate, a read-only operator's restriction is enforced nowhere.
type Gate struct {
	// Principal resolves the request's session to its operator (session.Handler.Principal).
	Principal func(*http.Request) (auth.Principal, bool)
	// Reverify is the mutation-path re-check (D12): the session's key must STILL be
	// active before a write is forwarded. Nil skips the re-check (tests compose it
	// separately; production always sets it).
	Reverify func(*http.Request) (auth.Principal, bool)
}

// maxIdentityBody bounds how much of a mutation body the identity check reads. Real
// decision bodies are well under 1 KiB; the bound only stops a hostile client from
// making the proxy buffer gigabytes.
const maxIdentityBody = 1 << 20

// infoInvokes are the two Information-capability invokes (T7): POST in shape, but they
// write nothing and propose no stance, so a read-scoped operator may run them (D11). The
// recommend_position invoke is deliberately ABSENT — it records an advisory Proposal in
// Governance, which makes it a write however reversible it looks.
var infoInvokes = map[string]bool{
	"/api/intelligence/capabilities/plan_remediation/invoke":      true,
	"/api/intelligence/capabilities/explain_vulnerability/invoke": true,
}

// isRead classifies a request for D11: read methods, plus the Information invokes.
func isRead(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return infoInvokes[r.URL.Path]
}

// Wrap enforces, in order: a session exists (401), the scope covers the route class
// (403), the body's identity claims match the session operator (403, D13), and — writes
// only — the key is still active (401, D12). Only a request that clears all four is
// forwarded; the API answers JSON problems, never login redirects, because a fetch
// cannot follow a redirect to an HTML form.
func (g Gate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := g.Principal(r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "authentication required", "sign in at /login")
			return
		}
		if isRead(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !p.AuthorizeWrite() {
			writeProblem(w, http.StatusForbidden, "read-only operator", "this operation records a decision and requires a write-capable key")
			return
		}
		if !g.identityMatches(w, r, p) {
			return // identityMatches wrote the problem
		}
		if g.Reverify != nil {
			if _, active := g.Reverify(r); !active {
				writeProblem(w, http.StatusUnauthorized, "key no longer active", "the session's API key was revoked or expired; sign in again")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// identityMatches enforces D13: if the mutation body claims an identity
// (proposer_id / actor_id), it must be the session's operator — a client that can send
// JSON can lie, and a lie must never reach an append-only audit trail. Validate-and-403
// over silent rewriting: refusing a lie loudly is the Themis direction, and a
// well-behaved SPA never notices the check exists. A body that is not JSON (or has no
// identity fields) passes — those routes' own validation owns their shape.
func (g Gate) identityMatches(w http.ResponseWriter, r *http.Request, p auth.Principal) bool {
	if r.Body == nil {
		return true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxIdentityBody))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "unreadable body", err.Error())
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw)) // the forwarded request needs the body back
	var claims struct {
		ProposerID *string `json:"proposer_id"`
		ActorID    *string `json:"actor_id"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return true
	}
	for _, c := range []*string{claims.ProposerID, claims.ActorID} {
		if c != nil && *c != p.Name {
			writeProblem(w, http.StatusForbidden, "identity mismatch",
				"the body claims an identity that is not the signed-in operator")
			return false
		}
	}
	return true
}
