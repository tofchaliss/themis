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

// documentPosts are mutation routes whose payload is a DOCUMENT, not a decision: they
// carry no identity claims for D13 to check, and their bodies routinely exceed
// maxIdentityBody (a real SBOM is megabytes). They skip the identity buffer and stream
// through intact. Measured 2026-08-19 (GUI-14): the buffer used to hand the proxy a
// TRUNCATED body under a full-length Content-Length, so every SBOM over 1 MiB died
// mid-forward as a fake 502 "node unreachable". Membership requires a route that is a
// pure document intake, never one whose body can name an actor.
var documentPosts = map[string]bool{
	"/api/evidence/evidence": true,
}

// statelessPosts are POST routes that RECORD NOTHING, so a read-scoped operator may use
// them (D11): the two Information-capability invokes (T7 — they propose no stance and
// nothing reaches Governance) and the publication preview (a non-recording render —
// "what WOULD this position render as", D9). The recommend_position invoke is
// deliberately ABSENT — it records an advisory Proposal in Governance, which makes it a
// write however reversible it looks. Membership requires positive evidence of
// statelessness, never "it looks read-ish".
var statelessPosts = map[string]bool{
	"/api/intelligence/capabilities/plan_remediation/invoke":      true,
	"/api/intelligence/capabilities/explain_vulnerability/invoke": true,
	"/api/communication/previews":                                 true,
}

// isRead classifies a request for D11: read methods, plus the stateless POSTs.
func isRead(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return statelessPosts[r.URL.Path]
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
		if !documentPosts[r.URL.Path] && !g.identityMatches(w, r, p) {
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
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxIdentityBody+1))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "unreadable body", err.Error())
		return false
	}
	// Over the cap ⇒ refuse HONESTLY (413), never forward: handing the proxy a truncated
	// body under a full-length Content-Length kills the outbound write and reads as a fake
	// 502 (GUI-14) — and skipping the check instead would let a padded body smuggle an
	// identity claim past D13. Decision bodies are tiny; a document belongs in documentPosts.
	if len(raw) > maxIdentityBody {
		writeProblem(w, http.StatusRequestEntityTooLarge, "body too large for a decision",
			"mutation bodies are capped at 1 MiB; document uploads use the evidence route")
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
