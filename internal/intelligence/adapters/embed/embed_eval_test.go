//go:build embed_eval

// Command: `make e2e-embed` (or `go test -tags=embed_eval -run TestEmbeddingModelEval -v ./...`).
//
// R5 — the embedding-model + what-to-embed evaluation (EDR-INTELLIGENCE-01 Rev 4). This is the
// opt-in harness that turns the R5 decision into a repeatable measurement: it embeds a small
// labeled corpus (findings grouped by shared component) with each candidate model and each
// text-composition variant, then reports how well a finding's same-component sibling ranks
// (recall@1 / recall@3 / MRR) plus embed latency. Higher recall + MRR = better precedent
// retrieval; lower latency = cheaper. It NEEDS a running Ollama (or any OpenAI-compatible server
// with embedding models) and SKIPS when none answers, so it is safe anywhere and is excluded
// from `make check`.
//
//	THEMIS_EMBED_URL     (default http://localhost:11434)
//	THEMIS_EMBED_MODELS  (default "nomic-embed-text"; comma-separated to compare several)
//	THEMIS_LLM_API_KEY   (optional bearer token)
//
// Example:
//	THEMIS_EMBED_MODELS=nomic-embed-text,bge-large,mxbai-embed-large make e2e-embed
package embed_test

import (
	"context"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/adapters/embed"
)

// evalItem is one labeled finding. Items sharing a group are "similar" (same component /
// bug-class, DIFFERENT CVE) — the retrieval target for RC-1.
type evalItem struct {
	id          string
	cve         string
	severity    string
	components  []string
	description string // a short bug summary — only the "+description" composition uses it
	group       string
}

// evalCorpus: 6 component groups × 2 findings (different CVEs on the same component). A good
// embedding + composition ranks a finding's same-group sibling near the top over the whole set.
var evalCorpus = []evalItem{
	{"openssl-a", "CVE-2022-3602", "critical", []string{"pkg:generic/openssl@3.0.6"}, "X.509 email 4-byte buffer overflow in punycode decoding", "openssl"},
	{"openssl-b", "CVE-2023-0286", "high", []string{"pkg:generic/openssl@1.1.1t"}, "X.400 address type confusion in X.509 GeneralName", "openssl"},

	{"log4j-a", "CVE-2021-44228", "critical", []string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}, "JNDI lookup remote code execution (Log4Shell)", "log4j"},
	{"log4j-b", "CVE-2021-45046", "critical", []string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0"}, "incomplete Log4Shell fix, DoS and RCE", "log4j"},

	{"libxml2-a", "CVE-2022-29824", "high", []string{"pkg:generic/libxml2@2.9.13"}, "integer overflow leading to buffer overflow in xmlBuf", "libxml2"},
	{"libxml2-b", "CVE-2016-9318", "medium", []string{"pkg:generic/libxml2@2.9.4"}, "XML external entity (XXE) expansion", "libxml2"},

	{"pyyaml-a", "CVE-2020-14343", "critical", []string{"pkg:pypi/pyyaml@5.3.1"}, "arbitrary code execution via FullLoader", "pyyaml"},
	{"pyyaml-b", "CVE-2020-1747", "critical", []string{"pkg:pypi/pyyaml@5.3"}, "arbitrary code execution via yaml.load without SafeLoader", "pyyaml"},

	{"openssh-a", "CVE-2023-38408", "critical", []string{"pkg:generic/openssh@9.3"}, "remote code execution in ssh-agent PKCS#11 forwarding", "openssh"},
	{"openssh-b", "CVE-2020-14145", "medium", []string{"pkg:generic/openssh@8.3"}, "observable discrepancy allows MITM during key exchange", "openssh"},

	{"glibc-a", "CVE-2023-4911", "high", []string{"pkg:generic/glibc@2.34"}, "Looney Tunables buffer overflow in ld.so GLIBC_TUNABLES", "glibc"},
	{"glibc-b", "CVE-2021-3999", "high", []string{"pkg:generic/glibc@2.34"}, "off-by-one buffer overflow in getcwd", "glibc"},
}

// composition is one "what to embed" variant under test.
type composition struct {
	name    string
	compose func(evalItem) string
}

var compositions = []composition{
	{"components", func(it evalItem) string { return strings.Join(it.components, " ") }},
	{"components+severity", func(it evalItem) string { return embed.SubjectText(it.severity, it.components) }}, // production
	{"components+severity+cve", func(it evalItem) string { return it.cve + " " + embed.SubjectText(it.severity, it.components) }},
	{"components+severity+description", func(it evalItem) string { return embed.SubjectText(it.severity, it.components) + " " + it.description }},
}

type metrics struct {
	recall1, recall3, mrr float64
	avgLatency            time.Duration
}

func TestEmbeddingModelEval(t *testing.T) {
	base := envOr("THEMIS_EMBED_URL", "http://localhost:11434")
	models := splitCSV(envOr("THEMIS_EMBED_MODELS", "nomic-embed-text"))
	apiKey := os.Getenv("THEMIS_LLM_API_KEY")
	hc := &http.Client{Timeout: 30 * time.Second}

	t.Logf("corpus: %d findings across %d component groups; higher recall/MRR + lower latency = better",
		len(evalCorpus), groupCount())
	t.Logf("%-22s %-32s %8s %8s %6s %10s", "model", "composition", "recall@1", "recall@3", "MRR", "avg_embed")

	anyRan := false
	for _, model := range models {
		emb := embed.NewOllamaEmbedder(base, model, hc).WithAPIKey(apiKey)
		if _, err := emb.Embed(context.Background(), "connectivity probe"); err != nil {
			t.Logf("SKIP model %q — unreachable at %s: %v", model, base, err)
			continue
		}
		anyRan = true
		for _, comp := range compositions {
			m := evaluate(t, emb, comp)
			t.Logf("%-22s %-32s %8.2f %8.2f %6.2f %10s",
				model, comp.name, m.recall1, m.recall3, m.mrr, m.avgLatency.Round(time.Millisecond))
		}
	}
	if !anyRan {
		t.Skipf("no embedding model reachable at %s (set THEMIS_EMBED_URL / THEMIS_EMBED_MODELS)", base)
	}
}

// evaluate embeds the whole corpus with one composition and scores same-group sibling retrieval.
func evaluate(t *testing.T, emb *embed.OllamaEmbedder, comp composition) metrics {
	t.Helper()
	vecs := make([][]float32, len(evalCorpus))
	var total time.Duration
	for i, it := range evalCorpus {
		start := time.Now()
		v, err := emb.Embed(context.Background(), comp.compose(it))
		total += time.Since(start)
		if err != nil {
			t.Fatalf("embed %s (%s): %v", it.id, comp.name, err)
		}
		vecs[i] = v
	}

	var r1, r3, mrrSum, queries float64
	for i := range evalCorpus {
		type scored struct {
			j int
			s float64
		}
		ranked := make([]scored, 0, len(evalCorpus)-1)
		for j := range evalCorpus {
			if j != i {
				ranked = append(ranked, scored{j, cosine(vecs[i], vecs[j])})
			}
		}
		sort.SliceStable(ranked, func(a, b int) bool { return ranked[a].s > ranked[b].s })

		rank := 0
		for pos, r := range ranked {
			if evalCorpus[r.j].group == evalCorpus[i].group {
				rank = pos + 1
				break
			}
		}
		if rank == 0 {
			continue // no sibling in the corpus
		}
		queries++
		if rank == 1 {
			r1++
		}
		if rank <= 3 {
			r3++
		}
		mrrSum += 1.0 / float64(rank)
	}
	if queries == 0 {
		return metrics{avgLatency: total / time.Duration(len(evalCorpus))}
	}
	return metrics{
		recall1:    r1 / queries,
		recall3:    r3 / queries,
		mrr:        mrrSum / queries,
		avgLatency: total / time.Duration(len(evalCorpus)),
	}
}

func groupCount() int {
	seen := map[string]struct{}{}
	for _, it := range evalCorpus {
		seen[it.group] = struct{}{}
	}
	return len(seen)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
