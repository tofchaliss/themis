package readapi

import "net/http"

// credentialHint names the likely cause of a 401/403 from a peer node in the error itself, so a
// refused read does not read as a broken peer. It is shared by every client in this package —
// the Governance projection reads, the precedent reads, the Registry walk and the proposal push
// — because the operator's remedy is the same one variable in all four cases.
//
// peer is the node that refused ("Governance", "Registry"). The key is never included.
func credentialHint(apiKey string, status int, peer string) string {
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return ""
	}
	if apiKey == "" {
		return " — this call sent no X-API-Key; set THEMIS_API_KEY on this node (a read-scoped key is enough for the reads; the autonomous proposal push needs a write-capable one)"
	}
	return " — this call sent an X-API-Key " + peer + " refused; check THEMIS_API_KEY is current and has the scope this call needs"
}
