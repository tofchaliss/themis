package architecture

// EDR-INTAKE-01 B2: the Evidence -> Registry seam gains EXACTLY ONE write — find or
// create a VERSION under a project that already exists — and the bound is structural
// rather than a comment asking for restraint. D7's wall ("a write from Evidence into
// Registry is neither an event nor a read") is narrowed, not removed: a typo in a
// Product or Project name must stay a refusal, and it does because there is no verb
// here that could create either.
//
// This is the assertion the EDR promises ("an architecture test asserts the seam
// exposes no other write"). It is written against the seam's EXPORTED types rather than
// its call sites, because a second write would arrive as a new method on one of them
// long before anybody called it — and the exported surface is what a future caller can
// reach for. The registry's own `UpsertRelease` verb therefore lives on an unexported
// interface inside the adapter: a write the package cannot offer anyone is not a second
// write, and anything that re-exported it would be caught here.

import (
	"go/types"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// `module` is this suite's own module path, declared once in architecture_test.go and
// shared by every file in package `architecture`.
const (
	evidenceApp        = module + "/internal/evidence/app"
	evidenceSubjectRef = module + "/internal/evidence/adapters/subjectref"
)

// seamReads are the seam's READ methods, named one by one. An allow-list rather than a
// name heuristic: "a method starting with Get is a read" is a convention a future
// method can quietly break, while a name missing from this list fails the test and
// forces the question "is that a write?" to be answered deliberately.
var seamReads = map[string]bool{
	"ReleaseExists":      true, // does this release id exist (Evidence's SubjectRef port)
	"ProductIDByName":    true, // exact product name -> id, abstaining
	"ProjectIDByName":    true, // exact project name under a product -> id
	"ReleaseIDByVersion": true, // exact version under a project -> id
	"ProductOfRelease":   true, // release -> project -> owning product (B7's authorization hop)
	"Resolve":            true, // the resolver's own read-only answer
}

// theOneWrite is the single write the seam may expose, by name. ONE name, not two: the
// registry's `UpsertRelease` verb is reachable only through an unexported interface
// inside the adapter, so the exported surface offers exactly this method and nothing
// else that could write. Anything else is a second write and fails this test.
const theOneWrite = "FindOrCreateRelease"

// writeShape is what that operation looks like, pinned so a widening cannot arrive as
// an extra parameter on the method that already exists: a project id and a version in,
// an id and the `created` answer out. A fourth parameter would be the beginning of
// "create whatever is missing", which is the decision D7 refused.
var writeShape = struct{ params, results []string }{
	params:  []string{"context.Context", "string", "string"},
	results: []string{"string", "bool", "error"},
}

func TestEvidenceRegistrySeamExposesOneWrite(t *testing.T) {
	pkgs := loadTyped(t, evidenceApp, evidenceSubjectRef)

	// 1. The port itself: ONE method, and no product or project verb to reach for.
	port := lookupInterface(t, pkgs[evidenceApp], "ReleaseProvisioner")
	if n := port.NumMethods(); n != 1 {
		t.Fatalf("app.ReleaseProvisioner has %d methods, want exactly 1 — the interface's shape IS B2's bound", n)
	}
	if got := port.Method(0).Name(); got != theOneWrite {
		t.Errorf("the one write is %q, want %s", got, theOneWrite)
	}

	// 2. The seam: every method it EXPOSES is one of the named reads, or that one
	// write — under that one name, because a second name for the same operation is a
	// second thing a future caller can reach for.
	var writes []string
	for name, m := range exportedMethods(t, pkgs[evidenceSubjectRef]) {
		method := strings.SplitN(name, ".", 2)[1]
		if seamReads[method] {
			continue
		}
		if method != theOneWrite {
			t.Errorf("%s is neither one of the seam's documented reads nor its one write (%s); "+
				"a second write into Registry is a decision, not an implementation detail (EDR-INTAKE-01 B2)", name, theOneWrite)
			continue
		}
		writes = append(writes, name)
		if got, want := signatureShape(m.Type()), writeShape; got.params != nil &&
			(strings.Join(got.params, ",") != strings.Join(want.params, ",") ||
				strings.Join(got.results, ",") != strings.Join(want.results, ",")) {
			t.Errorf("%s takes (%s) and returns (%s), want (%s) -> (%s) — it may create a version under an existing project and nothing more",
				name, strings.Join(got.params, ", "), strings.Join(got.results, ", "),
				strings.Join(want.params, ", "), strings.Join(want.results, ", "))
		}
		for _, forbidden := range []string{"Product", "Project"} {
			if strings.Contains(method, forbidden) {
				t.Errorf("%s names %s: intake creates the version only, under identity a human already registered", name, forbidden)
			}
		}
	}
	sort.Strings(writes)
	// Exactly one, counted: zero would mean the seam lost its write, and more than one
	// means two exported types can each write into Registry — which is the shape this
	// test exists to refuse, whatever the second one is called.
	if len(writes) != 1 {
		t.Errorf("the seam's exported write surface is %v, want exactly one method (%s)", writes, theOneWrite)
	}
	t.Logf("the seam's write surface: %v", writes)
}

// signatureShape reduces a method to its parameter and result TYPES, which is what the
// pin is about: names and receivers differ between an interface method and the concrete
// one that satisfies it, while the shape must not.
func signatureShape(t types.Type) struct{ params, results []string } {
	var out struct{ params, results []string }
	sig, ok := t.(*types.Signature)
	if !ok {
		return out
	}
	for i := 0; i < sig.Params().Len(); i++ {
		out.params = append(out.params, sig.Params().At(i).Type().String())
	}
	for i := 0; i < sig.Results().Len(); i++ {
		out.results = append(out.results, sig.Results().At(i).Type().String())
	}
	return out
}

func loadTyped(t *testing.T, patterns ...string) map[string]*packages.Package {
	t.Helper()
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("%d load error(s)", n)
	}
	out := map[string]*packages.Package{}
	for _, p := range pkgs {
		out[p.PkgPath] = p
	}
	for _, want := range patterns {
		if out[want] == nil {
			t.Fatalf("package %s did not load", want)
		}
	}
	return out
}

func lookupInterface(t *testing.T, p *packages.Package, name string) *types.Interface {
	t.Helper()
	obj := p.Types.Scope().Lookup(name)
	if obj == nil {
		t.Fatalf("%s.%s is not declared", p.PkgPath, name)
	}
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		t.Fatalf("%s.%s is not an interface", p.PkgPath, name)
	}
	return iface
}

// exportedMethods is every exported method the package's exported types expose, keyed
// "Type.Method" — interface methods and concrete methods alike, because the seam is
// both (the port and the adapter that satisfies it).
func exportedMethods(t *testing.T, p *packages.Package) map[string]types.Object {
	t.Helper()
	out := map[string]types.Object{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		tn, ok := obj.(*types.TypeName)
		if !ok || !obj.Exported() {
			continue
		}
		if iface, ok := tn.Type().Underlying().(*types.Interface); ok {
			for i := 0; i < iface.NumMethods(); i++ {
				if m := iface.Method(i); m.Exported() {
					out[name+"."+m.Name()] = m
				}
			}
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		for _, recv := range []types.Type{named, types.NewPointer(named)} {
			for _, sel := range typeutilMethods(recv) {
				if sel.Exported() {
					out[name+"."+sel.Name()] = sel
				}
			}
		}
	}
	return out
}

// typeutilMethods is the method set of t, without pulling in a helper package for one
// loop.
func typeutilMethods(t types.Type) []*types.Func {
	ms := types.NewMethodSet(t)
	out := make([]*types.Func, 0, ms.Len())
	for i := 0; i < ms.Len(); i++ {
		if fn, ok := ms.At(i).Obj().(*types.Func); ok {
			out = append(out, fn)
		}
	}
	return out
}
