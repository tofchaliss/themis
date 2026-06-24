package findingset

import (
	"path/filepath"
	"testing"
)

func TestKeyStringAndSnapshot(t *testing.T) {
	if KeyString("pkg:apk/busybox@1.0", "CVE-1", "distro_osv") != "pkg:apk/busybox@1.0|CVE-1|distro_osv" {
		t.Fatal("unexpected key")
	}
	got := Snapshot([]string{"b", "a", "b", "c"})
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("snapshot = %v", got)
	}
}

func TestDiff(t *testing.T) {
	added, removed := Diff([]string{"a", "b"}, []string{"b", "c"})
	if len(added) != 1 || added[0] != "c" {
		t.Fatalf("added = %v", added)
	}
	if len(removed) != 1 || removed[0] != "a" {
		t.Fatalf("removed = %v", removed)
	}
	a2, r2 := Diff([]string{"x"}, []string{"x"})
	if len(a2) != 0 || len(r2) != 0 {
		t.Fatalf("expected no diff, got +%v -%v", a2, r2)
	}
}

type fakeT struct{ failed bool }

func (f *fakeT) Helper()                          {}
func (f *fakeT) Fatalf(string, ...any)            { f.failed = true }

func TestAssertGoldenUpdateThenMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.golden")
	keys := []string{"k2", "k1"}

	t.Setenv("UPDATE_GOLDEN", "1")
	ft := &fakeT{}
	AssertGolden(ft, path, keys)
	if ft.failed {
		t.Fatal("update write should not fail")
	}

	t.Setenv("UPDATE_GOLDEN", "0")
	ft = &fakeT{}
	AssertGolden(ft, path, keys)
	if ft.failed {
		t.Fatal("match against just-written golden should pass")
	}

	// Drift fails.
	ft = &fakeT{}
	AssertGolden(ft, path, []string{"k1", "k3"})
	if !ft.failed {
		t.Fatal("expected drift failure")
	}

	// Missing golden file fails (without update).
	ft = &fakeT{}
	AssertGolden(ft, filepath.Join(t.TempDir(), "missing.golden"), keys)
	if !ft.failed {
		t.Fatal("expected missing-file failure")
	}
}
