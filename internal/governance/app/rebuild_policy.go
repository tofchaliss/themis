package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The rebuild policy record (EDR-REBUILD-01 D2, D9, D11 item 4; step R1). This file stores and
// reads the INSTALLATION policy with its version and its change history. It evaluates nothing
// against a Release and publishes nothing: wiring the rule to a trigger is step R2, and Product
// and Release policies are step R1a.

// Rebuild policy scope kinds. Step R1 writes the installation scope only; the column exists so
// that R1a adds the two override kinds without a second table.
const (
	RebuildScopeInstallation = "installation"
)

var (
	// ErrInvalidRebuildPolicy is returned when the record cannot be stored: an unknown severity
	// floor or mode, or a cool-down outside its bounds. Nothing is stored.
	ErrInvalidRebuildPolicy = errors.New("governance: invalid rebuild policy")
	// ErrRebuildPolicyActorRequired is returned when a change names no person. A policy that can
	// start builds needs a name on every change (D9).
	ErrRebuildPolicyActorRequired = errors.New("governance: a rebuild policy change must name its actor")
)

// RebuildPolicyRecord is one stored version of a policy.
type RebuildPolicyRecord struct {
	ScopeKind string
	ScopeID   string
	// Version counts the changes of this scope's policy from 1. 0 means nothing is stored and
	// the shipped defaults are in force.
	Version   int
	Policy    domain.RebuildPolicy
	UpdatedAt time.Time
	UpdatedBy string
}

// RebuildPolicyStore is the persistence seam.
type RebuildPolicyStore interface {
	// RebuildPolicy returns the current record of one scope; found is false when none is stored.
	RebuildPolicy(ctx context.Context, scopeKind, scopeID string) (rec RebuildPolicyRecord, found bool, err error)
	// PutRebuildPolicy stores the next version of rec's scope and appends it to the history in
	// one transaction. It sets and returns the new version; the caller's Version is ignored.
	PutRebuildPolicy(ctx context.Context, rec RebuildPolicyRecord) (RebuildPolicyRecord, error)
	// RebuildPolicyHistory returns every version of one scope, newest first.
	RebuildPolicyHistory(ctx context.Context, scopeKind, scopeID string) ([]RebuildPolicyRecord, error)
}

// RebuildPolicyService reads and changes the installation rebuild policy.
type RebuildPolicyService struct {
	store RebuildPolicyStore
	clock Clock
}

// NewRebuildPolicyService wires the service.
func NewRebuildPolicyService(store RebuildPolicyStore, clock Clock) *RebuildPolicyService {
	return &RebuildPolicyService{store: store, clock: clock}
}

// Installation returns the installation policy. With nothing stored it is the shipped default
// (D2) at version 0, so a reader can tell "never set" from "set to the same values".
func (s *RebuildPolicyService) Installation(ctx context.Context) (RebuildPolicyRecord, error) {
	rec, found, err := s.store.RebuildPolicy(ctx, RebuildScopeInstallation, "")
	if err != nil {
		return RebuildPolicyRecord{}, err
	}
	if !found {
		return RebuildPolicyRecord{ScopeKind: RebuildScopeInstallation, Policy: domain.DefaultRebuildPolicy()}, nil
	}
	return rec, nil
}

// PutInstallation stores a new version of the installation policy.
func (s *RebuildPolicyService) PutInstallation(ctx context.Context, p domain.RebuildPolicy, actor string) (RebuildPolicyRecord, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return RebuildPolicyRecord{}, ErrRebuildPolicyActorRequired
	}
	if !p.Valid() {
		return RebuildPolicyRecord{}, ErrInvalidRebuildPolicy
	}
	return s.store.PutRebuildPolicy(ctx, RebuildPolicyRecord{
		ScopeKind: RebuildScopeInstallation, Policy: p, UpdatedAt: s.clock.Now().UTC(), UpdatedBy: actor,
	})
}

// InstallationHistory returns every stored version of the installation policy, newest first.
func (s *RebuildPolicyService) InstallationHistory(ctx context.Context) ([]RebuildPolicyRecord, error) {
	return s.store.RebuildPolicyHistory(ctx, RebuildScopeInstallation, "")
}
