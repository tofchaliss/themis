package subjectref_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/app"
)

// The one write the seam exposes (EDR-INTAKE-01 B2), satisfied at COMPILE time: the
// app ring's port and this adapter cannot drift apart without this line breaking
// first, and the port has no product or project verb for the adapter to grow one from.
var _ app.ReleaseProvisioner = (*subjectref.Provisioner)(nil)

// fakeWriter is the registry write seam from a struct. It records what crossed, so a
// test can assert the provisioner passes the project and the version through rather
// than deriving either of them.
type fakeWriter struct {
	id                       string
	created                  bool
	err                      error
	calls                    int
	gotProjectID, gotVersion string
}

func (f *fakeWriter) UpsertRelease(_ context.Context, projectID, version string) (string, bool, error) {
	f.calls++
	f.gotProjectID, f.gotVersion = projectID, version
	return f.id, f.created, f.err
}

// TestProvisionerDelegatesUpsertRelease — the provisioner translates a verb and
// decides nothing: the id, the `created` answer and the uniqueness rule behind them are
// Registry's (B4), and `created=false` has to survive the hop or a retry would look
// like a second Release.
func TestProvisionerDelegatesUpsertRelease(t *testing.T) {
	for _, tc := range []struct {
		name    string
		created bool
	}{
		{"created", true},
		{"found", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &fakeWriter{id: "rel-9", created: tc.created}
			id, created, err := subjectref.NewProvisioner(w).FindOrCreateRelease(context.Background(), "proj-1", "R1918.001")
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if id != "rel-9" || created != tc.created {
				t.Errorf("got (%q, %v), want (%q, %v) — the registry's answer, unchanged", id, created, "rel-9", tc.created)
			}
			if w.calls != 1 {
				t.Errorf("the writer was called %d time(s), want once", w.calls)
			}
			if w.gotProjectID != "proj-1" || w.gotVersion != "R1918.001" {
				t.Errorf("wrote project %q version %q, want them carried through verbatim — Themis never normalizes a version (B2)",
					w.gotProjectID, w.gotVersion)
			}
		})
	}
}

// TestProvisionerPassesAStoreFailureThrough — a create that could not be made is a
// statement about Themis, and it must reach the app ring as one: intake reports the
// attempt `failed` and returns the cause, rather than inventing a reason about the
// document (B7's step 8 produces no refusal of its own).
func TestProvisionerPassesAStoreFailureThrough(t *testing.T) {
	boom := errors.New("registry: dial tcp: connection refused")
	id, created, err := subjectref.NewProvisioner(&fakeWriter{err: boom}).
		FindOrCreateRelease(context.Background(), "proj-1", "R1918.001")
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the cause to survive", err)
	}
	if id != "" || created {
		t.Errorf("got (%q, %v), want nothing named on a failure", id, created)
	}
}
