// Package proxy is the dashboard's same-origin reverse proxy to the node read APIs
// (EDR-GUI-01 D1/D4/D5). It exists because a browser cannot be the integration point
// for six ports: the nodes set no CORS headers (correctly — they serve services, not
// browsers), and with auth enabled the node's X-API-Key must never reach browser
// JavaScript. The proxy solves both at one seam: the page talks to its own origin
// (`/api/<node>/…`), and the key is attached server-side.
//
// It is deliberately a separate, driver-free package rather than code in `cmd`: the
// spike's first live defect (a capability-id 404 the compiler could not see) lived in
// exactly this path-rewriting seam, and a seam that caused a measured defect earns
// tests — which means it earns a package (D7). Phase 2 extends this package with the
// scope gate (D11) and identity validation (D13); the route table those need is the
// same one the constructor builds here.
package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
)

// Config wires the proxy. Every field is supplied by the composition root from env.
type Config struct {
	// Targets maps each node name the frontend addresses ("knowledge", "governance",
	// …) to its base URL. The names are the frontend's stable vocabulary; the URLs
	// carry the ports, so the page stays ignorant of deployment topology.
	Targets map[string]string
	// APIKey, when non-empty, is attached as X-API-Key to every forwarded request
	// (the NODE key, D4 — it states "the dashboard may read", never who is asking).
	// Empty = no header (an auth-off dev deployment).
	APIKey string
}

// Proxy routes /api/<node>/<rest> to <target>/api/v1/<rest> with key custody.
type Proxy struct {
	byNode map[string]*httputil.ReverseProxy
	nodes  string // sorted node list, for the unknown-node error body
}

// New builds the per-node reverse proxies, validating every target URL up front —
// a bad URL is a deployment error and must fail the boot, not the first request.
func New(cfg Config) (*Proxy, error) {
	byNode := make(map[string]*httputil.ReverseProxy, len(cfg.Targets))
	names := make([]string, 0, len(cfg.Targets))
	for node, target := range cfg.Targets {
		base, err := url.Parse(target)
		if err != nil {
			return nil, err
		}
		names = append(names, node)
		prefix := "/api/" + node
		p := &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(base)
				// /api/<node>/x → <target>/api/v1/x: the frontend never learns ports
				// or versions, the same property release-posture.sh gets from env vars.
				r.Out.URL.Path = "/api/v1" + strings.TrimPrefix(r.In.URL.Path, prefix)
				// Key custody is the proxy's job, never the page's: whatever key a
				// browser supplied is dropped, and only the configured node key goes out.
				r.Out.Header.Del("X-API-Key")
				if cfg.APIKey != "" {
					r.Out.Header.Set("X-API-Key", cfg.APIKey)
				}
			},
		}
		// A dead node answers 502 with a JSON problem body rather than an empty
		// reply, so the frontend renders "node unreachable" instead of a parse error.
		p.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeProblem(w, http.StatusBadGateway, "node unreachable", node)
		}
		byNode[node] = p
	}
	sort.Strings(names)
	return &Proxy{byNode: byNode, nodes: strings.Join(names, ", ")}, nil
}

// ServeHTTP expects the FULL request path (mount the Proxy at "/api/"): it resolves
// the node from the second segment and forwards the rest. An unknown node is a 404
// problem naming the valid nodes — a frontend typo should read as a typo, not as a
// missing card.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/")
	node, _, _ := strings.Cut(rest, "/")
	rp, ok := p.byNode[node]
	if !ok {
		writeProblem(w, http.StatusNotFound, "unknown node", "valid: "+p.nodes)
		return
	}
	rp.ServeHTTP(w, r)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Hand-rolled to keep the error path allocation-trivial and dependency-free;
	// both fields originate in code, never from request input.
	_, _ = w.Write([]byte(`{"title":"` + title + `","detail":"` + detail + `"}`))
}
