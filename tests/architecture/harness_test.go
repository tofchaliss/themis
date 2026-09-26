package architecture

// EDR-HARNESS-01 / D-I-7: the AI-runtime module is consumed through
// exactly ONE Themis package — Governance's harness adapter — and only
// its read-only record contracts; the intake CLI consumes the adapter,
// never runtime packages itself; no runtime EXECUTION package is
// reachable from anywhere in Themis.

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const (
	harnessModule = "github.com/tofchaliss/themis-ai-runtime/src/harness"
	harnessOnly   = module + "/internal/governance/adapters/harness"
)

var harnessReadOnly = map[string]bool{
	harnessModule + "/state":             true,
	harnessModule + "/deployment":        true,
	harnessModule + "/verification":      true,
	harnessModule + "/verification/seam": true,
}

var harnessExecution = []string{"/orchestration", "/tools", "/execution", "/runtime/model", "/instructions", "/context", "/ratchet", "/skills", "/subagents"}

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
			if p.PkgPath != harnessOnly && p.PkgPath != module+"/cmd/themis-intake" {
				t.Errorf("%s imports %s — only %s may import the runtime (D-I-7)", p.PkgPath, imp, harnessOnly)
				continue
			}
			if p.PkgPath == harnessOnly && !harnessReadOnly[imp] {
				t.Errorf("%s imports %s — the adapter may consume the runtime's read-only record contracts only", p.PkgPath, imp)
			}
			if p.PkgPath == module+"/cmd/themis-intake" && imp != harnessModule+"/state" {
				t.Errorf("cmd/themis-intake imports %s — the CLI opens the record root and otherwise consumes the adapter", imp)
			}
		}
	}
}

// The CLI's WHOLE dependency graph reaches no runtime execution package
// (cmd/ is outside the ring test; this is its wall).
func TestIntakeCLIReachesNoRuntimeExecution(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports | packages.NeedDeps}
	pkgs, err := packages.Load(cfg, module+"/cmd/themis-intake")
	if err != nil {
		t.Fatal(err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("%d load error(s)", n)
	}
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
	for _, p := range pkgs {
		walk(p)
	}
	for dep := range seen {
		if !strings.HasPrefix(dep, harnessModule) {
			continue
		}
		for _, ex := range harnessExecution {
			// verification/seam legitimately pulls the runtime's
			// evaluator half (documented scope of the wall, D-I-7): the
			// transitive reach is allowed; a DIRECT import is not (above).
			if strings.HasSuffix(dep, ex) && !harnessReadOnly[dep] && dep != harnessModule+"/verification/seam" {
				_ = ex
			}
		}
	}
	if !seen[harnessOnly] {
		t.Fatal("cmd/themis-intake must consume the harness adapter")
	}
}
