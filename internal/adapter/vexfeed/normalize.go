package vexfeed

import "strings"

// namespaceAliases maps SBOM namespace segments to vendor VEX namespaces.
var namespaceAliases = map[string]string{
	"rhel": "redhat",
	"alma": "almalinux",
}

func normalizeCase(purl string) string {
	return strings.ToLower(strings.TrimSpace(purl))
}

func normalizeRPMNamespace(p parsedPURL) parsedPURL {
	out := p
	ns := strings.ToLower(p.Namespace)
	if alias, ok := namespaceAliases[ns]; ok {
		out.Namespace = alias
	}
	// rocky/linux → rocky
	if ns == "rocky" && strings.HasPrefix(strings.ToLower(p.Name), "linux/") {
		out.Name = strings.TrimPrefix(strings.ToLower(p.Name), "linux/")
	}
	if strings.EqualFold(p.Namespace, "rocky/linux") {
		out.Namespace = "rocky"
	}
	// SBOM may encode rocky/linux as namespace with name starting after linux/
	parts := strings.Split(ns, "/")
	if len(parts) == 2 && parts[0] == "rocky" && parts[1] == "linux" {
		out.Namespace = "rocky"
	}
	return out
}

func namespacesEquivalent(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	if a == b {
		return true
	}
	if alias, ok := namespaceAliases[a]; ok && alias == b {
		return true
	}
	if alias, ok := namespaceAliases[b]; ok && alias == a {
		return true
	}
	// rhel ↔ redhat handled above; rocky/linux ↔ rocky
	if (a == "rocky/linux" || a == "rocky") && (b == "rocky/linux" || b == "rocky") {
		return true
	}
	return false
}
