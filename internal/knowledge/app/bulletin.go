package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The PSIRT bulletin register (EDR-PSIRT-01 revision 3): what an admin wrote about an issue,
// kept with every change in its history.

// Bulletin change actions, as the history records them.
const (
	BulletinCreated = "created"
	BulletinUpdated = "updated"
	BulletinRemoved = "removed"
)

var (
	// ErrBulletinNotFound: no live bulletin has this id.
	ErrBulletinNotFound = errors.New("bulletin not found")
	// ErrBulletinConflict: another live bulletin already has this bulletin ID or this CVE.
	ErrBulletinConflict = errors.New("another bulletin already has this bulletin ID or CVE")
	// ErrBulletinForbidden: the edit rule refused this editor (domain.CanEditBulletin).
	ErrBulletinForbidden = errors.New("only an admin may change the bulletin register")
	// ErrBulletinsUnavailable: no register is wired on this node.
	ErrBulletinsUnavailable = errors.New("the bulletin register is not available on this node")
)

// BulletinChange is one row of a bulletin's history: who changed it, when, and the bulletin
// before and after (nil before a create, nil after a removal).
type BulletinChange struct {
	At     time.Time
	Actor  string
	Action string
	Before *domain.Bulletin
	After  *domain.Bulletin
}

// BulletinStore keeps the register. Every write appends its history row in the same
// transaction; a removal is a tombstone, never a delete. A duplicate live bulletin ID or CVE is
// ErrBulletinConflict; an unknown or removed id is ErrBulletinNotFound.
type BulletinStore interface {
	ListBulletins(ctx context.Context) ([]domain.Bulletin, error)
	GetBulletin(ctx context.Context, id string) (domain.Bulletin, error)
	CreateBulletin(ctx context.Context, b domain.Bulletin) error
	UpdateBulletin(ctx context.Context, before, after domain.Bulletin) error
	RemoveBulletin(ctx context.Context, b domain.Bulletin, actor string, at time.Time) error
	BulletinHistory(ctx context.Context, id string) ([]BulletinChange, error)
}

// BulletinService serves the register.
type BulletinService struct {
	store BulletinStore
	ids   IDGenerator
	clock Clock
}

// NewBulletinService wires the register; a nil store refuses with ErrBulletinsUnavailable.
func NewBulletinService(store BulletinStore, ids IDGenerator, clock Clock) *BulletinService {
	return &BulletinService{store: store, ids: ids, clock: clock}
}

func (s *BulletinService) ready() error {
	if s == nil || s.store == nil {
		return ErrBulletinsUnavailable
	}
	return nil
}

// List returns every live bulletin, newest report date first (R3).
func (s *BulletinService) List(ctx context.Context) ([]domain.Bulletin, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.store.ListBulletins(ctx)
}

// Create adds a bulletin for the editor; actor is recorded on it and in its history.
func (s *BulletinService) Create(ctx context.Context, in domain.BulletinInput, editor domain.BulletinEditor, actor string) (domain.Bulletin, error) {
	if err := s.ready(); err != nil {
		return domain.Bulletin{}, err
	}
	if !domain.CanEditBulletin(editor) {
		return domain.Bulletin{}, ErrBulletinForbidden
	}
	norm, err := domain.NormalizeBulletin(in)
	if err != nil {
		return domain.Bulletin{}, err
	}
	now := s.clock.Now().UTC()
	if norm.ReportDate.IsZero() {
		norm.ReportDate = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	}
	b := domain.Bulletin{ID: s.ids.NewID(), BulletinInput: norm, CreatedAt: now, CreatedBy: actor, UpdatedAt: now, UpdatedBy: actor}
	if err := s.store.CreateBulletin(ctx, b); err != nil {
		return domain.Bulletin{}, err
	}
	return b, nil
}

// Update replaces a bulletin's typed fields; a zero report date keeps the one it had.
func (s *BulletinService) Update(ctx context.Context, id string, in domain.BulletinInput, editor domain.BulletinEditor, actor string) (domain.Bulletin, error) {
	if err := s.ready(); err != nil {
		return domain.Bulletin{}, err
	}
	if !domain.CanEditBulletin(editor) {
		return domain.Bulletin{}, ErrBulletinForbidden
	}
	norm, err := domain.NormalizeBulletin(in)
	if err != nil {
		return domain.Bulletin{}, err
	}
	before, err := s.store.GetBulletin(ctx, id)
	if err != nil {
		return domain.Bulletin{}, err
	}
	if norm.ReportDate.IsZero() {
		norm.ReportDate = before.ReportDate
	}
	after := before
	after.BulletinInput, after.UpdatedAt, after.UpdatedBy = norm, s.clock.Now().UTC(), actor
	if err := s.store.UpdateBulletin(ctx, before, after); err != nil {
		return domain.Bulletin{}, err
	}
	return after, nil
}

// Remove tombstones a bulletin: it leaves the register, its history stays.
func (s *BulletinService) Remove(ctx context.Context, id string, editor domain.BulletinEditor, actor string) error {
	if err := s.ready(); err != nil {
		return err
	}
	if !domain.CanEditBulletin(editor) {
		return ErrBulletinForbidden
	}
	b, err := s.store.GetBulletin(ctx, id)
	if err != nil {
		return err
	}
	return s.store.RemoveBulletin(ctx, b, actor, s.clock.Now().UTC())
}

// History returns every change of one bulletin, oldest first, a removed one included.
func (s *BulletinService) History(ctx context.Context, id string) ([]BulletinChange, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.store.BulletinHistory(ctx, id)
}
