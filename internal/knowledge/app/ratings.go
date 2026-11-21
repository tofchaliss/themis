package app

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// Source ratings (EDR-SCORING-01 S2). The service records what a source published as immutable
// observations and publications, with lifecycle events, validations and identity groupings
// beside them. It decides nothing about selection; Governance does that (S4).

// RatingPrior is the state one revision is recorded against, read inside the store's
// transaction while the document is locked.
type RatingPrior struct {
	// LatestObservationID and LatestFingerprint name the document's most recent observation
	// ("" when the document was never seen). A revision equal to the LATEST one is unchanged;
	// one equal only to an older revision is a change back, recorded as a new revision.
	LatestObservationID string
	LatestFingerprint   string
	// Active are the document's publications with no terminal event.
	Active []domain.SourceRating
	// Members are every publication of the CVE, as the linking rule sees them.
	Members []domain.IdentityMember
	// Groupings are the latest recorded grouping per set of the CVE.
	Groupings map[string]domain.Grouping
}

// RatingWrite is everything one revision appends. Every record is new; nothing is updated.
type RatingWrite struct {
	Observation *domain.SourceObservation
	Seen        domain.SeenEvent
	Ratings     []domain.SourceRating
	Events      []domain.RatingEvent
	Validations []domain.RatingValidation
	Links       []domain.AssessmentLink
}

// RatingKey names the document a revision belongs to, and the revision's fingerprint.
type RatingKey struct {
	CVE         string
	Source      string
	DocumentRef string
	Fingerprint string
}

// RatingStore is the append-only rating store.
type RatingStore interface {
	// RecordRevision locks the document, reads the prior state, asks build for the write and
	// appends it, all in one transaction.
	RecordRevision(ctx context.Context, key RatingKey, build func(RatingPrior) (RatingWrite, error)) error
	// RatingsForCVE reads every observation, publication, terminal event, validation and the
	// latest grouping of one CVE.
	RatingsForCVE(ctx context.Context, cve string) (RatingsSnapshot, error)
}

// RatingsSnapshot is the stored source truth of one CVE.
type RatingsSnapshot struct {
	Observations []domain.SourceObservation
	Ratings      []domain.SourceRating
	Events       map[string]domain.RatingEvent
	Validations  map[string]domain.RatingValidation
	Groupings    map[string]domain.Grouping
}

// RatingService records and reads source ratings.
type RatingService struct {
	store RatingStore
	ids   IDGenerator
	clock Clock
}

// NewRatingService wires the rating ports.
func NewRatingService(store RatingStore, ids IDGenerator, clock Clock) *RatingService {
	return &RatingService{store: store, ids: ids, clock: clock}
}

// Link causes recorded on an AssessmentLink.
const (
	LinkCausePublicationAdded    = "publication_added"
	LinkCausePublicationTerminal = "publication_terminal"
)

// Record records one source revision for a CVE. An unchanged revision appends a seen event
// only (R-S7). A new revision appends the observation, its new publications with a validation
// each, the terminal events a complete revision implies (EDR 3.4) and a grouping event for each
// set whose grouping changed (EDR 3.2a).
func (s *RatingService) Record(ctx context.Context, cve value.CVEID, in domain.ObservationInput) error {
	if cve.IsZero() {
		return errors.New("knowledge: zero cve")
	}
	if err := in.Validate(); err != nil {
		return err
	}
	key := RatingKey{CVE: cve.String(), Source: in.Source, DocumentRef: in.DocumentRef, Fingerprint: in.Fingerprint()}
	now := s.clock.Now().UTC()
	return s.store.RecordRevision(ctx, key, func(prior RatingPrior) (RatingWrite, error) {
		return s.build(key, in, prior, now), nil
	})
}

func (s *RatingService) build(key RatingKey, in domain.ObservationInput, prior RatingPrior, now time.Time) RatingWrite {
	seen := domain.SeenEvent{Source: in.Source, DocumentRef: in.DocumentRef, FetchedAt: now, Fetch: in.Fetch}
	if prior.LatestObservationID != "" && prior.LatestFingerprint == key.Fingerprint {
		seen.ObservationID, seen.Outcome = prior.LatestObservationID, domain.SeenUnchanged
		return RatingWrite{Seen: seen}
	}
	apps := sortedSet(in.Applicability)
	obs := domain.SourceObservation{
		ID: s.ids.NewID(), CVE: key.CVE, Source: in.Source, Feed: in.Feed, DocumentRef: in.DocumentRef,
		Revision: in.Revision, UpdatedAt: in.UpdatedAt, Fingerprint: key.Fingerprint, Complete: in.Complete,
		Applicability: apps, SeverityWord: strings.TrimSpace(in.SeverityWord), FirstObservedAt: now,
	}
	seen.ObservationID, seen.Outcome = obs.ID, domain.SeenNewRevision
	w := RatingWrite{Observation: &obs, Seen: seen}

	plan := domain.PlanRevision(prior.Active, in.Ratings, in.Complete)
	inherited := strings.Join(apps, ",")
	for _, r := range plan.New {
		sr := domain.SourceRating{
			ID: s.ids.NewID(), ObservationID: obs.ID, CVE: key.CVE, Source: in.Source,
			DocumentRef: in.DocumentRef, Feed: in.Feed, PublishedRating: r, RecordedAt: now,
		}
		if strings.TrimSpace(r.AssertedContext) == "" {
			sr.InheritedContext = inherited // D12: the only path from applicability to selection
		}
		w.Ratings = append(w.Ratings, sr)
		w.Validations = append(w.Validations, domain.ValidateRating(sr, now))
	}
	terminal := map[string]bool{}
	for _, e := range plan.Events {
		ev := domain.RatingEvent{RatingID: e.RatingID, Kind: e.Kind, CausedBy: obs.ID, SourceTime: in.UpdatedAt, LearnedAt: now}
		if e.ReplacedByIndex >= 0 {
			ev.ReplacedBy = w.Ratings[e.ReplacedByIndex].ID
		}
		w.Events = append(w.Events, ev)
		terminal[e.RatingID] = true
	}

	members := make([]domain.IdentityMember, 0, len(prior.Members)+len(w.Ratings))
	for _, m := range prior.Members {
		if terminal[m.RatingID] {
			m.Active = false
		}
		members = append(members, m)
	}
	for _, r := range w.Ratings {
		members = append(members, domain.MemberOf(r, domain.RatingActive))
	}
	cause := LinkCausePublicationAdded
	if len(w.Ratings) == 0 {
		cause = LinkCausePublicationTerminal
	}
	next := domain.GroupAll(members)
	setKeys := make([]string, 0, len(next))
	for k := range next {
		setKeys = append(setKeys, k)
	}
	sort.Strings(setKeys)
	for _, k := range setKeys {
		g, before := next[k], prior.Groupings[k]
		if g.Equal(before) {
			continue
		}
		w.Links = append(w.Links, domain.AssessmentLink{
			CVE: key.CVE, SetKey: k, Grouping: g, Changes: domain.DiffGrouping(before, g),
			PolicyVersion: domain.LinkPolicyVersion, Cause: cause, At: now,
		})
	}
	return w
}

func sortedSet(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if _, dup := seen[s]; s == "" || dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// RatingView is one publication with everything derived about it.
type RatingView struct {
	Rating     domain.SourceRating
	Status     domain.RatingStatus
	Event      *domain.RatingEvent
	Validation *domain.RatingValidation
	Identity   domain.GroupingEntry
}

// RatingsView is the read model of one CVE's source ratings.
type RatingsView struct {
	CVE          string
	Observations []domain.SourceObservation
	Ratings      []RatingView
}

// RatingsForCVE reads one CVE's source ratings, each with its derived status, its validation and
// its identity under the latest grouping. Publications come in recording order.
func (s *RatingService) RatingsForCVE(ctx context.Context, cve string) (RatingsView, error) {
	snap, err := s.store.RatingsForCVE(ctx, cve)
	if err != nil {
		return RatingsView{}, err
	}
	identity := map[string]domain.GroupingEntry{}
	for _, g := range snap.Groupings {
		for _, e := range g {
			identity[e.RatingID] = e
		}
	}
	out := RatingsView{CVE: cve, Observations: snap.Observations}
	for _, r := range snap.Ratings {
		v := RatingView{Rating: r, Identity: identity[r.ID]}
		if ev, ok := snap.Events[r.ID]; ok {
			v.Event = &ev
		}
		v.Status = domain.StatusOf(v.Event)
		if val, ok := snap.Validations[r.ID]; ok {
			v.Validation = &val
		}
		out.Ratings = append(out.Ratings, v)
	}
	return out, nil
}
