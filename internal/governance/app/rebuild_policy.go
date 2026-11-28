package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The rebuild policy records (EDR-REBUILD-01 D2, D9, D11, D17; steps R1 and R1a). This file
// stores and reads the installation policy and the optional Product and Release policies, each
// with its own version and change history, and answers which one is in force for a Release.
// It evaluates no Finding and publishes nothing: wiring the rule to a trigger is step R2.

// Rebuild policy scope kinds, as stored. They are the three levels of D11.
const (
	RebuildScopeInstallation = string(domain.RebuildLevelInstallation)
	RebuildScopeProduct      = string(domain.RebuildLevelProduct)
	RebuildScopeRelease      = string(domain.RebuildLevelRelease)
)

var (
	// ErrInvalidRebuildPolicy is returned when the record cannot be stored: an unknown severity
	// floor or mode, or a cool-down outside its bounds. Nothing is stored.
	ErrInvalidRebuildPolicy = errors.New("governance: invalid rebuild policy")
	// ErrRebuildPolicyActorRequired is returned when a change names no person. A policy that can
	// start builds needs a name on every change (D9).
	ErrRebuildPolicyActorRequired = errors.New("governance: a rebuild policy change must name its actor")
	// ErrRebuildPolicyScopeInvalid is returned when an override names no Product or Release.
	ErrRebuildPolicyScopeInvalid = errors.New("governance: a rebuild policy override needs a product or a release id")
	// ErrRebuildPolicyNotFound is returned when the override to remove does not exist.
	ErrRebuildPolicyNotFound = errors.New("governance: no rebuild policy is stored for this scope")
	// ErrRebuildPolicyIdentityUnavailable is returned when the Product of a Release cannot be
	// read. The policy in force is then unknown: the installation policy must not stand in for
	// a Product policy that could not be looked up.
	ErrRebuildPolicyIdentityUnavailable = errors.New("governance: the product of this release could not be established")
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
	// Removed is set on a history entry that records the removal of an override: the values are
	// the ones in force until then, the actor and time are the removal's. Never set on a policy
	// in force.
	Removed bool
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
	// RemoveRebuildPolicy deletes the policy in force for one scope and appends the removal to
	// the history as the next version, in one transaction. found is false when none was stored.
	RemoveRebuildPolicy(ctx context.Context, scopeKind, scopeID string, at time.Time, by string) (rec RebuildPolicyRecord, found bool, err error)
	// RebuildPolicies returns every policy in force: installation, then Products, then Releases,
	// each group ordered by scope id.
	RebuildPolicies(ctx context.Context) ([]RebuildPolicyRecord, error)
}

// RebuildPolicyService reads and changes the rebuild policies.
type RebuildPolicyService struct {
	store    RebuildPolicyStore
	identity ProductOfRelease // nil: the policy in force for a Release cannot be answered
	clock    Clock
}

// NewRebuildPolicyService wires the service.
func NewRebuildPolicyService(store RebuildPolicyStore, clock Clock) *RebuildPolicyService {
	return &RebuildPolicyService{store: store, clock: clock}
}

// WithIdentity attaches the Registry seam that names a Release's Product. Without it InForce
// answers ErrRebuildPolicyIdentityUnavailable.
func (s *RebuildPolicyService) WithIdentity(identity ProductOfRelease) *RebuildPolicyService {
	s.identity = identity
	return s
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

// PutInstallation stores a new version of the installation policy. The time is cut to the
// microsecond, the database's precision, so the answer to a change and a later read agree.
func (s *RebuildPolicyService) PutInstallation(ctx context.Context, p domain.RebuildPolicy, actor string) (RebuildPolicyRecord, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return RebuildPolicyRecord{}, ErrRebuildPolicyActorRequired
	}
	if !p.Valid() {
		return RebuildPolicyRecord{}, ErrInvalidRebuildPolicy
	}
	return s.store.PutRebuildPolicy(ctx, RebuildPolicyRecord{
		ScopeKind: RebuildScopeInstallation, Policy: p, UpdatedAt: s.now(), UpdatedBy: actor,
	})
}

func (s *RebuildPolicyService) now() time.Time {
	return s.clock.Now().UTC().Truncate(time.Microsecond)
}

// InstallationHistory returns every stored version of the installation policy, newest first.
func (s *RebuildPolicyService) InstallationHistory(ctx context.Context) ([]RebuildPolicyRecord, error) {
	return s.store.RebuildPolicyHistory(ctx, RebuildScopeInstallation, "")
}

// overrideScope checks that an override names a Product or a Release and returns the cleaned id.
func overrideScope(level domain.RebuildPolicyLevel, id string) (string, error) {
	id = strings.TrimSpace(id)
	if (level != domain.RebuildLevelProduct && level != domain.RebuildLevelRelease) || id == "" {
		return "", ErrRebuildPolicyScopeInvalid
	}
	return id, nil
}

// Override returns the policy stored for one Product or one Release; found is false when that
// scope has none and takes the next level's.
func (s *RebuildPolicyService) Override(ctx context.Context, level domain.RebuildPolicyLevel, id string) (RebuildPolicyRecord, bool, error) {
	id, err := overrideScope(level, id)
	if err != nil {
		return RebuildPolicyRecord{}, false, err
	}
	return s.store.RebuildPolicy(ctx, string(level), id)
}

// PutOverride stores a new version of one Product's or one Release's policy. The record is
// whole (D11 item 2): it does not inherit single fields from the level above.
func (s *RebuildPolicyService) PutOverride(ctx context.Context, level domain.RebuildPolicyLevel, id string, p domain.RebuildPolicy, actor string) (RebuildPolicyRecord, error) {
	id, err := overrideScope(level, id)
	if err != nil {
		return RebuildPolicyRecord{}, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return RebuildPolicyRecord{}, ErrRebuildPolicyActorRequired
	}
	if !p.Valid() {
		return RebuildPolicyRecord{}, ErrInvalidRebuildPolicy
	}
	return s.store.PutRebuildPolicy(ctx, RebuildPolicyRecord{
		ScopeKind: string(level), ScopeID: id, Policy: p, UpdatedAt: s.now(), UpdatedBy: actor,
	})
}

// RemoveOverride removes one Product's or one Release's policy, so that scope takes the next
// level's again. The removal is a history entry with its actor. The installation policy cannot
// be removed.
func (s *RebuildPolicyService) RemoveOverride(ctx context.Context, level domain.RebuildPolicyLevel, id, actor string) (RebuildPolicyRecord, error) {
	id, err := overrideScope(level, id)
	if err != nil {
		return RebuildPolicyRecord{}, err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return RebuildPolicyRecord{}, ErrRebuildPolicyActorRequired
	}
	rec, found, err := s.store.RemoveRebuildPolicy(ctx, string(level), id, s.now(), actor)
	if err != nil {
		return RebuildPolicyRecord{}, err
	}
	if !found {
		return RebuildPolicyRecord{}, ErrRebuildPolicyNotFound
	}
	return rec, nil
}

// OverrideHistory returns every version of one Product's or one Release's policy, newest
// first, removals included.
func (s *RebuildPolicyService) OverrideHistory(ctx context.Context, level domain.RebuildPolicyLevel, id string) ([]RebuildPolicyRecord, error) {
	id, err := overrideScope(level, id)
	if err != nil {
		return nil, err
	}
	return s.store.RebuildPolicyHistory(ctx, string(level), id)
}

// List returns every policy in force in the installation (D11 item 3): the installation policy
// first (the shipped default at version 0 when none is stored), then the Product policies,
// then the Release policies.
func (s *RebuildPolicyService) List(ctx context.Context) ([]RebuildPolicyRecord, error) {
	recs, err := s.store.RebuildPolicies(ctx)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 || recs[0].ScopeKind != RebuildScopeInstallation {
		def := RebuildPolicyRecord{ScopeKind: RebuildScopeInstallation, Policy: domain.DefaultRebuildPolicy()}
		recs = append([]RebuildPolicyRecord{def}, recs...)
	}
	return recs, nil
}

// RebuildPolicyForRelease is the answer to "which policy applies to this Release" (D11 item 3,
// D17).
type RebuildPolicyForRelease struct {
	ReleaseID string
	ProductID string
	// InForce is the one record that applies, with its scope and version.
	InForce RebuildPolicyRecord
	// InstallationMode is the installation policy's mode, the ceiling of D17.
	InstallationMode domain.RebuildMode
	// ModeCeiling is the most the policies allow for this Release, and ModeSetBy which of them
	// set it. The Release's tags can only lower it (D17 value 3); they are read from step R2 on.
	ModeCeiling domain.RebuildMode
	ModeSetBy   string
}

// InForce resolves the policy in force for one Release: its own, else its Product's, else the
// installation's. It fails closed when the Product cannot be read.
func (s *RebuildPolicyService) InForce(ctx context.Context, releaseID string) (RebuildPolicyForRelease, error) {
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return RebuildPolicyForRelease{}, ErrRebuildPolicyScopeInvalid
	}
	if s.identity == nil {
		return RebuildPolicyForRelease{}, ErrRebuildPolicyIdentityUnavailable
	}
	productID, _, err := s.identity.ProductAndProjectOfRelease(ctx, releaseID)
	if err != nil || strings.TrimSpace(productID) == "" {
		return RebuildPolicyForRelease{}, ErrRebuildPolicyIdentityUnavailable
	}
	inst, err := s.Installation(ctx)
	if err != nil {
		return RebuildPolicyForRelease{}, err
	}
	out := RebuildPolicyForRelease{ReleaseID: releaseID, ProductID: productID, InForce: inst, InstallationMode: inst.Policy.Mode}
	var product, release *domain.RebuildPolicy
	prodRec, found, err := s.store.RebuildPolicy(ctx, RebuildScopeProduct, productID)
	if err != nil {
		return RebuildPolicyForRelease{}, err
	}
	if found {
		product, out.InForce = &prodRec.Policy, prodRec
	}
	relRec, found, err := s.store.RebuildPolicy(ctx, RebuildScopeRelease, releaseID)
	if err != nil {
		return RebuildPolicyForRelease{}, err
	}
	if found {
		release, out.InForce = &relRec.Policy, relRec
	}
	res := domain.ResolveRebuildPolicy(inst.Policy, product, release)
	out.ModeCeiling, out.ModeSetBy = res.ModeCeiling, res.ModeSetBy
	return out, nil
}
