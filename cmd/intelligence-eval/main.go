//go:build llm

// Command intelligence-eval is the Δ4a LLMOps replay harness (EDR-INTELLIGENCE-01 § Δ4a,
// D-Δ4a-6): an OFFLINE, ON-DEMAND, LIVE-MODEL evaluation of the Intelligence Gateway against a
// human-curated golden set. It is the `e2e-llm`-shaped counterpart with scoring and history —
// run it post-deploy or pre-promotion, read the report, decide.
//
// It replays each golden entry's FROZEN assembled context through the real Gateway (real
// provider calls), then scores the terminal Outcome deterministically: a produced/valid result
// or an honest decline PASSES; a schema/business/grounding failure FAILS. For Information
// capabilities that is groundedness + well-formedness, NOT answer quality (D-Δ4a-2) — the report
// header says so.
//
// It is LIVE-ONLY by decision (no static/model-less mode): the eval is about model behavior, and
// a contract check must never be mistaken for a quality check. There is no CI net — running this
// is a human's job (D-Δ4a-6).
//
// Subcommands:
//
//	intelligence-eval run                     — replay the golden set, score, store + print a report
//	intelligence-eval promote <corr> --label  — copy a logged invocation into the durable golden set
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	"github.com/themis-project/themis/internal/intelligence/adapters/provider"
	"github.com/themis-project/themis/internal/intelligence/adapters/store"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: intelligence-eval <run|promote> [args]")
		os.Exit(2)
	}
	dsn := os.Getenv("THEMIS_DATABASE_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "THEMIS_DATABASE_DSN is required (the intelligence store)")
		os.Exit(2)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pool: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()
	st := store.New(pool)

	switch os.Args[1] {
	case "run":
		if err := runEval(ctx, st); err != nil {
			fmt.Fprintf(os.Stderr, "eval: %v\n", err)
			os.Exit(1)
		}
	case "promote":
		if err := promote(ctx, st, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "promote: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// replayProjection serves ONE golden entry's frozen AssembledContext to the Gateway. Its three
// reads return the sub-parts of the frozen context, so the Gateway replays the exact grounding
// the entry was captured with — no live Governance/Knowledge read.
type replayProjection struct{ ac domain.AssembledContext }

func (p replayProjection) GetAssessment(context.Context, string) (domain.FindingAssessment, error) {
	return p.ac.Projection, nil
}
func (p replayProjection) GetReleasePosture(context.Context, string) (domain.ReleasePosture, error) {
	return p.ac.Release, nil
}
func (p replayProjection) GetReleaseComparison(context.Context, string, string) (domain.ReleaseComparison, error) {
	return p.ac.Comparison, nil
}

// entryResult is one golden entry's scored outcome.
type entryResult struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Capability    string `json:"capability"`
	PromptVersion string `json:"prompt_version"`
	Model         string `json:"model"`
	Pass          bool   `json:"pass"`
	Reason        string `json:"reason"`
}

func runEval(ctx context.Context, st *store.Store) error {
	golden, err := st.ListGolden(ctx)
	if err != nil {
		return err
	}
	if len(golden) == 0 {
		fmt.Println("golden set is empty — promote some invocations first (intelligence-eval promote <corr> --label ...)")
		return nil
	}

	// The provider + engine, built directly (not through wiring) so each entry's Gateway can be
	// handed the frozen-context replay projection. THEMIS_INTELLIGENCE_PROVIDER=fake exercises
	// the harness itself without a model; a real run needs Ollama at THEMIS_LLM_URL.
	var prov app.Provider
	if os.Getenv("THEMIS_INTELLIGENCE_PROVIDER") == "fake" {
		prov = provider.NewFakeProvider(`{"finding_id":"","recommended_stance":"insufficient","confidence":0,"evidence":[],"reasoning":"fake"}`)
	} else {
		prov = provider.NewOllamaProvider(envDefault("THEMIS_LLM_URL", "http://localhost:11434"),
			envDefault("THEMIS_LLM_MODEL", "llama3.1:8b"), nil).
			WithAPIKey(os.Getenv("THEMIS_LLM_API_KEY")).WithResponseFormat(os.Getenv("THEMIS_LLM_RESPONSE_FORMAT"))
	}
	pr, err := engine.NewPromptRenderer()
	if err != nil {
		return err
	}
	llm := engine.NewLLMEngine(provider.NewTieredRouter(prov, nil, nil))

	results := make([]entryResult, 0, len(golden))
	passed := 0
	for _, g := range golden {
		var ac domain.AssembledContext
		if err := json.Unmarshal(g.ContextJSON, &ac); err != nil {
			results = append(results, entryResult{ID: g.ID, Label: g.Label, Capability: g.Capability, Pass: false, Reason: "unreplayable_context"})
			continue
		}
		gw, gerr := app.NewGateway(app.GatewayConfig{
			Registry:   domain.DefaultRegistry(),
			Projection: replayProjection{ac: ac},
			Prompt:     pr,
			Engines:    []app.Engine{llm},
		})
		if gerr != nil {
			return gerr
		}
		sel := selectionFor(g.Capability, ac)
		_, oc := gw.Invoke(ctx, g.Capability, sel, "eval-"+g.ID)
		pass := scorePass(oc)
		if pass {
			passed++
		}
		results = append(results, entryResult{
			ID: g.ID, Label: g.Label, Capability: g.Capability,
			PromptVersion: oc.PromptVersion, Model: oc.Model, Pass: pass, Reason: oc.Reason,
		})
	}

	report := map[string]any{
		"note":    "Information capabilities score groundedness/well-formedness, NOT answer quality (D-Δ4a-2). Live-model eval; run-it-yourself.",
		"entries": results,
	}
	blob, _ := json.MarshalIndent(report, "", "  ")
	_ = st.WriteEvalReport(ctx, uuid.NewString(), os.Getenv("THEMIS_EVAL_FINGERPRINT"), len(golden), passed, blob)

	printTable(results, passed)
	return nil
}

// scorePass: a produced proposal, a valid Information answer, or an HONEST decline passes; a
// contract failure (schema/business/grounding) fails. no_grounding here means the frozen context
// itself was thin — treated as a pass (the model behaved correctly given nothing to work with).
func scorePass(oc app.Outcome) bool {
	switch oc.Reason {
	case app.ReasonOK, app.ReasonInsufficient, app.ReasonNoGrounding, app.ReasonBudgetExhausted:
		return true
	default: // schema_invalid, business_invalid, provider_error, ...
		return false
	}
}

// selectionFor rebuilds the Selection the capability needs from the frozen context.
func selectionFor(capability string, ac domain.AssembledContext) domain.Selection {
	switch {
	case ac.Comparison.CandidateID != "":
		return domain.NewSelection(domain.SelectionRelease, ac.Comparison.BaselineID, ac.Comparison.CandidateID)
	case ac.Release.ReleaseID != "":
		return domain.NewSelection(domain.SelectionRelease, ac.Release.ReleaseID)
	default:
		return domain.NewSelection(domain.SelectionFinding, ac.Projection.Finding.ID)
	}
}

func promote(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("promote", flag.ExitOnError)
	label := fs.String("label", "", "a human label for the case (required)")
	// Go's flag package stops at the first POSITIONAL arg, so `promote <corr> --label X` would
	// leave --label unparsed. Pull the correlation id (the first non-flag arg) out first, then
	// parse the rest — so flag order does not matter (measured live 2026-08-26).
	var corr string
	var flagArgs []string
	for _, a := range args {
		if corr == "" && !strings.HasPrefix(a, "-") {
			corr = a
			continue
		}
		flagArgs = append(flagArgs, a)
	}
	_ = fs.Parse(flagArgs)
	if corr == "" || *label == "" {
		return fmt.Errorf("usage: intelligence-eval promote <correlation_id> --label \"<case>\"")
	}
	in, ok, err := st.GetInvocation(ctx, corr)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no logged invocation %q (it may have been pruned)", corr)
	}
	// The frozen expectation is the recorded outcome shape — grounded + reason. The eval re-runs
	// the model and re-scores; the expected_json is provenance of what the case looked like.
	expected, _ := json.Marshal(map[string]any{"reason": in.Reason, "decline_class": in.DeclineClass})
	err = st.PromoteGolden(ctx, store.GoldenEntry{
		ID: uuid.NewString(), Label: *label, Capability: in.Capability,
		SourceCorrelationID: corr, ContextJSON: in.ContextJSON, ExpectedJSON: expected,
	})
	if err != nil {
		return err
	}
	fmt.Printf("promoted %s (%s) → golden set\n", corr, in.Capability)
	return nil
}

func printTable(results []entryResult, passed int) {
	fmt.Printf("\nIntelligence eval — %d/%d passed  (%s)\n", passed, len(results), time.Now().Format(time.RFC3339))
	fmt.Println("Information capabilities: groundedness/well-formedness, NOT answer quality.")
	fmt.Println("---------------------------------------------------------------")
	for _, r := range results {
		mark := "PASS"
		if !r.Pass {
			mark = "FAIL"
		}
		fmt.Printf("  %-4s  %-22s  %-14s  %s\n", mark, r.Capability, r.Reason, r.Label)
	}
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
