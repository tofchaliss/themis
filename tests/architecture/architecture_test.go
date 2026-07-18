// Package architecture holds module-wide architecture tests that enforce the
// context-first Clean Architecture rules (EDR-EVIDENCE-01 D9; Book III §3.5) which
// go-cleanarch's flat layer model cannot express:
//
//   - inward-only ring direction within each bounded context
//     (domain -> app -> adapters; dependencies point inward only), and
//   - no imports across bounded contexts (contexts collaborate solely via events
//     and read APIs).
//
// The shared kernel (internal/kernel) and the registry supporting context
// (internal/registry) are shared foundations and may be imported by any context.
package architecture

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const module = "github.com/themis-project/themis"

// boundedContexts are the greenfield context-first trees under internal/.
// Add a context here as it is scaffolded; the rules then apply automatically.
var boundedContexts = []string{
	"evidence",
	"knowledge",
	"governance",
	"communication",
	"intelligence",
}

// ringRank returns the Clean Architecture ring for a package within a context:
// domain (0, innermost) < app (1) < adapters (2, outermost). Dependencies may
// point only to the same or a lower rank within the same context.
func ringRank(pkgPath, ctx string) (rank int, isRing bool) {
	base := module + "/internal/" + ctx + "/"
	switch {
	case strings.HasPrefix(pkgPath, base+"domain"):
		return 0, true
	case strings.HasPrefix(pkgPath, base+"app"):
		return 1, true
	case strings.HasPrefix(pkgPath, base+"adapters"):
		return 2, true
	}
	return 0, false
}

func contextOf(pkgPath string) (string, bool) {
	for _, c := range boundedContexts {
		if strings.HasPrefix(pkgPath, module+"/internal/"+c+"/") {
			return c, true
		}
	}
	return "", false
}

// TestKernelIsLeaf enforces that the shared kernel (internal/kernel) imports nothing
// from any bounded context or from the registry supporting context — it is the
// dependency leaf everyone may import, and must never depend on them (EDR-KERNEL-01
// D3; the admission rule's "owned by no single context").
func TestKernelIsLeaf(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports}
	pkgs, err := packages.Load(cfg, module+"/internal/kernel/...")
	if err != nil {
		t.Fatalf("load kernel packages: %v", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("kernel packages contained %d load error(s)", n)
	}

	forbidden := append([]string{"registry"}, boundedContexts...)
	for _, p := range pkgs {
		for imp := range p.Imports {
			if !strings.HasPrefix(imp, module+"/internal/") {
				continue // stdlib / third-party is fine (e.g. id -> google/uuid)
			}
			for _, f := range forbidden {
				base := module + "/internal/" + f
				if imp == base || strings.HasPrefix(imp, base+"/") {
					t.Errorf("kernel leaf violation: %s imports %s — the kernel must depend on no context or the registry",
						p.PkgPath, imp)
				}
			}
		}
	}
}

// TestRegistrySupportingContext enforces that the registry — a supporting foundation
// beneath the pipeline — keeps inward-only rings (domain < app < adapters) and imports
// no pipeline context (it collaborates via its read API, e.g. ReleaseExists). It may
// import the kernel. Contexts may reference the registry (Book III §3.5), so the
// registry is deliberately not one of boundedContexts.
func TestRegistrySupportingContext(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports}
	pkgs, err := packages.Load(cfg, module+"/internal/registry/...")
	if err != nil {
		t.Fatalf("load registry packages: %v", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("registry packages contained %d load error(s)", n)
	}

	for _, p := range pkgs {
		rank, hasRing := ringRank(p.PkgPath, "registry")
		for imp := range p.Imports {
			if !strings.HasPrefix(imp, module+"/internal/") {
				continue
			}
			// (1) The registry must not import any pipeline context.
			for _, other := range boundedContexts {
				if strings.HasPrefix(imp, module+"/internal/"+other+"/") {
					t.Errorf("registry imports pipeline context: %s imports %s — collaborate via read APIs only",
						p.PkgPath, imp)
				}
			}
			// (2) Inward-only ring direction within the registry.
			if hasRing {
				if impRank, impIsRing := ringRank(imp, "registry"); impIsRing && impRank > rank {
					t.Errorf("registry ring violation: %s (ring %d) imports %s (ring %d) — dependencies must point inward",
						p.PkgPath, rank, imp, impRank)
				}
			}
		}
	}
}

func TestContextFirstArchitecture(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports}
	patterns := make([]string, 0, len(boundedContexts))
	for _, c := range boundedContexts {
		patterns = append(patterns, module+"/internal/"+c+"/...")
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatalf("load packages: %v", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("packages contained %d load error(s)", n)
	}

	for _, p := range pkgs {
		ctx, ok := contextOf(p.PkgPath)
		if !ok {
			continue
		}
		rank, hasRing := ringRank(p.PkgPath, ctx)
		for imp := range p.Imports {
			if !strings.HasPrefix(imp, module+"/internal/") {
				continue // stdlib / third-party — not an architecture concern here
			}

			// (1) No imports across bounded contexts.
			for _, other := range boundedContexts {
				if other == ctx {
					continue
				}
				if strings.HasPrefix(imp, module+"/internal/"+other+"/") {
					t.Errorf("cross-context import: %s imports %s — contexts collaborate via events + read APIs only",
						p.PkgPath, imp)
				}
			}

			// (2) Inward-only ring direction within the same context.
			if hasRing {
				if impRank, impIsRing := ringRank(imp, ctx); impIsRing && impRank > rank {
					t.Errorf("ring violation: %s (ring %d) imports %s (ring %d) — dependencies must point inward",
						p.PkgPath, rank, imp, impRank)
				}
			}
		}
	}
}
