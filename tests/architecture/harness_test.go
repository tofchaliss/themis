package architecture

// EDR-HARNESS-01 / D-I-7: the AI-runtime module is consumed through
// exactly ONE Themis package — Governance's harness adapter — and only
// its read-only record contracts; the intake CLI consumes the adapter,
// never runtime packages itself; and no other Themis binary links the
// runtime at all.
//
// The wall is a DIRECT-IMPORT wall, not a reachability wall, and these
// tests say so rather than implying more. The runtime's
// `verification/seam` imports the runtime's own evaluator half, which
// reaches `orchestration` and everything below it, so `themis-intake`
// LINKS runtime execution code that Themis never calls. That reach is
// pinned below so it cannot grow unnoticed.

import (
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const (
	harnessModule = "github.com/tofchaliss/themis-ai-runtime/src/harness"
	harnessOnly   = module + "/internal/governance/adapters/harness"
	intakeCLI     = module + "/cmd/themis-intake"
)

// The runtime packages the adapter may import DIRECTLY: the read-only
// record contracts, and nothing that executes.
var harnessReadOnly = map[string]bool{
	harnessModule + "/state":             true,
	harnessModule + "/deployment":        true,
	harnessModule + "/verification":      true,
	harnessModule + "/verification/seam": true,
}

// The runtime packages `themis-intake` transitively LINKS, measured.
// Everything past the four read-only contracts arrives through
// `verification/seam` → `orchestration` → … — linked, never called.
// Pinned because a change here is a decision about how much runtime
// Themis carries in a binary, not a build detail: a new entry means the
// seam's reach grew, and a missing one means it shrank and this list
// should shrink with it.
var harnessLinkedReach = map[string]bool{
	harnessModule + "/confine":             true,
	harnessModule + "/context":             true,
	harnessModule + "/decisions":           true,
	harnessModule + "/deployment":          true,
	harnessModule + "/execution":           true,
	harnessModule + "/instructions":        true,
	harnessModule + "/internal/llm":        true,
	harnessModule + "/internal/strictjson": true,
	harnessModule + "/orchestration":       true,
	harnessModule + "/runtime/model":       true,
	harnessModule + "/skills":              true,
	harnessModule + "/state":               true,
	harnessModule + "/tools":               true,
	harnessModule + "/verification":        true,
	harnessModule + "/verification/seam":   true,
}

func TestExactlyOneThemisPackageImportsTheHarness(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports}
	pkgs, err := packages.Load(cfg, module+"/internal/...", module+"/cmd/...")
	if err != nil {
		t.Fatal(err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("%d load error(s)", n)
	}
	for _, p := range pkgs {
		for imp := range p.Imports {
			if !strings.HasPrefix(imp, harnessModule) {
				continue
			}
			if p.PkgPath != harnessOnly && p.PkgPath != intakeCLI {
				t.Errorf("%s imports %s — only %s may import the runtime (D-I-7)", p.PkgPath, imp, harnessOnly)
				continue
			}
			if p.PkgPath == harnessOnly && !harnessReadOnly[imp] {
				t.Errorf("%s imports %s — the adapter may consume the runtime's read-only record contracts only", p.PkgPath, imp)
			}
			if p.PkgPath == intakeCLI && imp != harnessModule+"/state" {
				t.Errorf("cmd/themis-intake imports %s — the CLI opens the record root and otherwise consumes the adapter", imp)
			}
		}
	}
}

// The reach the direct-import wall actually leaves: pinned, and named
// as a consequence rather than a guarantee. A diff here is the signal
// that the runtime's read-only contracts stopped being a thin seam.
func TestIntakeCLIRuntimeReachIsPinned(t *testing.T) {
	reach := runtimeReach(t, intakeCLI)
	if !reach[harnessOnly] {
		t.Fatal("cmd/themis-intake must consume the harness adapter")
	}
	var linked []string
	for dep := range reach {
		if strings.HasPrefix(dep, harnessModule) {
			linked = append(linked, dep)
		}
	}
	sort.Strings(linked)
	for _, dep := range linked {
		if !harnessLinkedReach[dep] {
			t.Errorf("cmd/themis-intake now links %s, which is not in the pinned reach — the seam's blast radius grew; re-affirm it deliberately (EDR-HARNESS-01 D8)", dep)
		}
	}
	for dep := range harnessLinkedReach {
		if !reach[dep] {
			t.Errorf("%s is pinned in the reach but no longer linked — shrink the pin", dep)
		}
	}
}

// The guarantee D-I-1 actually makes: Governance's own service binary
// never links the record plane, and neither does any other node or the
// frozen monolith. The record plane is read by the human-operated
// bridge, on the host that holds it, and nowhere else.
func TestNoThemisBinaryButTheIntakeCLILinksTheRuntime(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports | packages.NeedDeps}
	pkgs, err := packages.Load(cfg, module+"/cmd/...")
	if err != nil {
		t.Fatal(err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("%d load error(s)", n)
	}
	for _, p := range pkgs {
		if p.PkgPath == intakeCLI {
			continue
		}
		for dep := range closure(p) {
			if strings.HasPrefix(dep, harnessModule) {
				t.Errorf("%s links %s — only %s may carry the runtime (D-I-1: the Governance service never reads the record plane)", p.PkgPath, dep, intakeCLI)
			}
		}
	}
}

// runtimeReach is the transitive import closure of one package pattern.
func runtimeReach(t *testing.T, pattern string) map[string]bool {
	t.Helper()
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports | packages.NeedDeps}
	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		t.Fatal(err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("%d load error(s)", n)
	}
	seen := map[string]bool{}
	for _, p := range pkgs {
		for dep := range closure(p) {
			seen[dep] = true
		}
	}
	return seen
}

func closure(root *packages.Package) map[string]bool {
	seen := map[string]bool{}
	var walk func(p *packages.Package)
	walk = func(p *packages.Package) {
		if seen[p.PkgPath] {
			return
		}
		seen[p.PkgPath] = true
		for _, d := range p.Imports {
			walk(d)
		}
	}
	walk(root)
	return seen
}
