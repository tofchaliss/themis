//go:build e2e

package pipeline

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/platform/auth"
)

// nodeKeys are the credentials of one auth-on pipeline: the operator's own key plus one per
// node that calls another node. The zero value is the auth-OFF runner — every field empty, so
// every client sends no header, which is exactly the behaviour a node with no THEMIS_API_KEY
// has.
//
// They are separate keys rather than one shared admin key on purpose: the deployment this test
// stands in for gives each node the SMALLEST scope its own calls need, and a single admin key
// everywhere would pass even if a client dropped the header on a read it only makes with write
// scope. The plaintext tokens live in this struct and are never logged.
type nodeKeys struct {
	operator      string // admin — the human/CI credential the test's own API calls carry
	knowledge     string // read  — Knowledge → Evidence (inventory, document, identity candidates)
	governance    string // read  — Governance → Registry / Knowledge / Evidence
	communication string // read  — Communication → Governance / Registry
}

// mintNodeKeys creates the four keys in the shared `auth` database through the SAME code path
// `cmd/authadmin create-key` uses (auth.GenerateKey + auth.Store.CreateKey), so what this test
// proves about a key is true of a key an operator mints.
func mintNodeKeys(t *testing.T, authDSN string) nodeKeys {
	t.Helper()
	pool := mustPool(t, authDSN)
	t.Cleanup(pool.Close)
	store := auth.NewStore(pool)

	mint := func(name string, scopes ...string) string {
		raw, hash, err := auth.GenerateKey()
		if err != nil {
			t.Fatalf("generate %s key: %v", name, err)
		}
		err = store.CreateKey(context.Background(), auth.APIKey{
			ID: "key-" + uuid.NewString(), Name: name, KeyHash: hash, Scopes: scopes,
		})
		if err != nil {
			t.Fatalf("create %s key: %v", name, err)
		}
		return raw
	}
	return nodeKeys{
		operator:      mint("e2e-operator", auth.ScopeAdmin),
		knowledge:     mint("knowledge-read", auth.ScopeRead),
		governance:    mint("governance-read", auth.ScopeRead),
		communication: mint("communication-read", auth.ScopeRead),
	}
}

// TestPipeline_SBOMToPublishedVEX_WithInboundAuthOnEveryNode is the proof that the inbound edge
// can be switched ON everywhere: the SAME SBOM → published-OpenVEX scenario as the baseline,
// with THEMIS_AUTH_DATABASE_DSN set on every node of the pipeline (Registry, Evidence,
// Knowledge, Governance, Communication) and every node holding its own key.
//
// Before this, turning auth on broke the pipeline at its first hop, which is why Evidence,
// Registry and Governance were found running AUTH DISABLED on the enterprise VM (2026-10-13):
// Knowledge's inventory read sent no credential, so an uploaded SBOM correlated to nothing and
// no Finding was ever opened. The failure was silent — a 401 in a bus reader's log — so the
// deployment looked healthy and had simply stopped seeing vulnerabilities.
//
// What it exercises, end to end, with every peer authenticating:
//
//	Knowledge    → Evidence    the canonical inventory (correlation's input)
//	Governance   → Registry    the blast-radius multiplier under the posture read
//	Governance   → Knowledge   the FindingAssessment projection
//	Communication→ Governance  the Enterprise Position behind the OpenVEX document
//
// Intelligence is NOT part of this harness (it needs a model provider, and its client would
// have to be wired into Governance before Governance exists). Its four seams — the assessment
// and precedent reads, the Registry walk, the proposal push — and Governance's call INTO it are
// covered by the header tests beside each client.
func TestPipeline_SBOMToPublishedVEX_WithInboundAuthOnEveryNode(t *testing.T) {
	p := newPipeline(t, options{pgPort: pgPortAuth, auth: true})
	if p.apiKey == "" {
		t.Fatal("the auth-on runner must hold an operator key")
	}

	// An unauthenticated call must be refused, or this test would pass on a node that silently
	// mounted its API open and prove nothing about credentials.
	unauth := &pipeline{registryURL: p.registryURL}
	assertUnauthorized(t, unauth, p.evidenceURL+"/api/v1/evidence/none")
	assertUnauthorized(t, unauth, p.governanceURL+"/api/v1/releases/none/posture")

	findingID := p.sbomToPublishedVEX(t)

	// Governance → Knowledge, explicitly: the assessment projection carries the Knowledge half
	// only if that read authenticated. Governance degrades this seam to "the Finding alone"
	// rather than failing (EDR-GOVERNANCE-01 T10/D16), so a 401 here is invisible in the
	// scenario above — the one place an unauthenticated read would quietly cost knowledge.
	var assessment struct {
		Knowledge struct {
			CVE string `json:"cve"`
		} `json:"knowledge"`
	}
	p.getJSON(t, p.governanceURL+"/api/v1/findings/"+findingID+"/assessment", &assessment)
	if assessment.Knowledge.CVE != targetCVE {
		t.Errorf("assessment knowledge half = %+v, want %s — Governance's authenticated read of Knowledge degraded",
			assessment.Knowledge, targetCVE)
	}

	t.Log("pipeline OK with inbound auth enabled on EVERY node (registry, evidence, knowledge, governance, communication)")
}

// assertUnauthorized confirms a node refuses a request with no X-API-Key. It uses a keyless
// pipeline value so the request is built exactly as the test's own calls are, minus the header.
func assertUnauthorized(t *testing.T, keyless *pipeline, url string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp := keyless.do(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET %s without a key = %d, want 401 — this node is NOT authenticated", url, resp.StatusCode)
	}
}
