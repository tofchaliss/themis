package subjectref

import "context"

// releaseWriter is the seam's WRITE half, and it is UNEXPORTED on purpose: the package's
// public write surface is then exactly one method — [Provisioner.FindOrCreateRelease] —
// which is the property EDR-INTAKE-01 B2 asks for and an architecture test enforces. A
// second name for the same operation on the exported API would be a second thing a
// future caller could reach for, and the registry's own verb is not Evidence's to offer.
//
// It is one method because that is the bound B2 draws: find or create a version under a
// project that already exists. There is no product or project verb here, so intake is
// structurally incapable of creating either — a typo in a human-owned name stays a
// refusal, which is the hazard D7 refused `create_if_missing` over.
//
// It carries primitives only, exactly like the read half: `UpsertRelease` is the
// registry's own verb for its idempotent find-or-create (B4), and the registry's types
// and error values stay on the registry's side of the composition root. The
// implementation is `cmd/evidence`'s `registryReader`, delegating to the registry
// store's `UpsertRelease` — so the uniqueness rule, the id and the `created` answer are
// Registry's, and Evidence learns an id without learning how Releases work. A caller
// cannot NAME this type from outside the package, and does not need to: it passes a
// value that satisfies it.
type releaseWriter interface {
	UpsertRelease(ctx context.Context, projectID, version string) (id string, created bool, err error)
}

// Provisioner satisfies the app's ReleaseProvisioner port over that one write. It is
// the whole of what intake can write into Registry.
//
// The translation it performs is the point of its existence: the app ring asks to
// "find or create a release", which is the question B2 permits, and the registry's
// "upsert" vocabulary stops at this adapter — the same shape the read half has, where
// the registry's ambiguity sentinel becomes this context's own.
type Provisioner struct{ reg releaseWriter }

// NewProvisioner builds the provisioner over the registry write seam. The parameter's
// type is unexported, which costs a caller nothing — `cmd/evidence` passes its seam
// value and never names the type.
func NewProvisioner(reg releaseWriter) *Provisioner { return &Provisioner{reg: reg} }

// FindOrCreateRelease returns the canonical release id for the version under projectID,
// creating it only if it is not there, and says which of the two happened. It is the
// package's ONLY exported write.
//
// It is called at step 8 of the intake order and nowhere else — after every border
// check, immediately before filing — so a refused submission creates nothing.
func (p *Provisioner) FindOrCreateRelease(ctx context.Context, projectID, version string) (string, bool, error) {
	return p.reg.UpsertRelease(ctx, projectID, version)
}
