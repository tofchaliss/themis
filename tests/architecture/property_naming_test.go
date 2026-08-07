package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// greenfieldRoots are the go-forward trees, mirroring GREENFIELD_DIRS in the Makefile. The
// frozen v0.3.x tree is excluded for the same reason CI's property job excludes it (CI-PROP-1):
// it is reference-only, so a naming violation there cannot be fixed.
var greenfieldRoots = []string{
	"../../internal/kernel", "../../internal/registry", "../../internal/evidence",
	"../../internal/knowledge", "../../internal/governance", "../../internal/communication",
	"../../internal/intelligence", "../../internal/platform",
}

// TestRapidPropertiesAreNamedForTheDeepRun enforces the naming convention the property gate
// selects on.
//
// `make test-property` runs `-run 'Property|Prop_'`, so a rapid.Check test named anything else
// executes ONLY at rapid's built-in default of 100 examples under `make test`, and never in the
// 1000 / 5000 / 20000-example sweeps. That is a silent hole: the test looks like it is covered
// by the property gate, reports pass, and has never been swept.
//
// Found the hard way on 2026-08-07 — `TestReconcile_OrderIndependent`, the D2 determinism
// guarantee and the single most important invariant in Knowledge, had been excluded from every
// deep run the project ever did. A convention enforced by nothing is a convention that has
// already been broken somewhere you have not looked yet.
func TestRapidPropertiesAreNamedForTheDeepRun(t *testing.T) {
	for _, root := range greenfieldRoots {
		root := root
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return err
			}
			for _, fn := range rapidTestFuncs(t, path) {
				if !strings.Contains(fn, "Property") && !strings.HasPrefix(fn, "TestProp_") {
					t.Errorf("%s: %s uses rapid but its name matches neither `Property` nor `Prop_`, "+
						"so `make test-property` never selects it and it is capped at rapid's default "+
						"100 examples — rename it to end in `Property`", path, fn)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

// rapidTestFuncs returns the names of top-level Test functions in path whose body mentions
// rapid. Parsing rather than grepping so a function is attributed correctly regardless of how
// the call is formatted or how far into the body it sits.
func rapidTestFuncs(t *testing.T, path string) []string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(src), "pgregory.net/rapid") {
		return nil // cheap pre-filter: no rapid import, nothing to check
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Body == nil {
			continue
		}
		if mentionsRapid(fn.Body) {
			out = append(out, fn.Name.Name)
		}
	}
	return out
}

// mentionsRapid reports whether the body references the rapid package — either rapid.Check
// directly or a helper taking *rapid.T.
func mentionsRapid(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "rapid" {
			found = true
			return false
		}
		return true
	})
	return found
}
