package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/adapters/http/gen"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type snapStore struct {
	snap app.RatingsSnapshot
	err  error
}

func (s snapStore) RecordRevision(context.Context, app.RatingKey, func(app.RatingPrior) (app.RatingWrite, error)) error {
	return nil
}

func (s snapStore) RatingsForCVE(context.Context, string) (app.RatingsSnapshot, error) { return s.snap, s.err }

type nilIDs struct{}

func (nilIDs) NewID() string { return "" }

func ratingsServer(t *testing.T, repo app.Repository, ratings *app.RatingService) *httptest.Server {
	t.Helper()
	h := knhttp.NewHandler(app.NewReadService(repo, fakeProjection{}), app.NewFeedHealthService(fakeFeedStore{}, feedClock{}))
	if ratings != nil {
		h = h.WithRatings(ratings)
	}
	srv := httptest.NewServer(h.Router())
	t.Cleanup(srv.Close)
	return srv
}

func getRatings(t *testing.T, srv *httptest.Server, id string) (*http.Response, gen.SourceRatings) {
	t.Helper()
	resp, err := http.Get(srv.URL + "/faultlines/" + id + "/ratings")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out gen.SourceRatings
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp, out
}

func TestGetFaultlineRatings(t *testing.T) {
	card := sampleCard(t)
	repo := fakeRepo{card: card, found: true}
	at := time.Unix(1_700_000_000, 0).UTC()
	snap := app.RatingsSnapshot{
		Observations: []domain.SourceObservation{
			{ID: "o1", Source: "redhat", Feed: "f", DocumentRef: "redhat:CVE-2024-1", Revision: "7", Complete: true,
				UpdatedAt: domain.ParseSourceTime("2024-01-02T03:04:05"), Applicability: []string{"cpe:x"}, SeverityWord: "Important", FirstObservedAt: at},
			{ID: "o2", Source: "nvd", DocumentRef: "nvd:CVE-2024-1", FirstObservedAt: at},
		},
		Ratings: []domain.SourceRating{
			{ID: "r1", ObservationID: "o1", Source: "redhat", Feed: "f", InheritedContext: "cpe:x", RecordedAt: at,
				PublishedRating: domain.PublishedRating{Assessor: "redhat", Publisher: "redhat", Version: "3.1",
					Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U", StatedScore: 9.8, HasStatedScore: true, SeverityWord: "Critical"}},
			{ID: "r2", ObservationID: "o2", Source: "nvd", RecordedAt: at,
				PublishedRating: domain.PublishedRating{Assessor: "nvd", NVDType: "Primary", Version: "2.0", Vector: "AV:N"}},
		},
		Events: map[string]domain.RatingEvent{"r1": {RatingID: "r1", Kind: domain.RatingSuperseded, CausedBy: "o3", ReplacedBy: "r3",
			SourceTime: domain.ParseSourceTime("2024-02-01T00:00:00Z"), LearnedAt: at}},
		Validations: map[string]domain.RatingValidation{
			"r1": {RatingID: "r1", CalculatorVersion: domain.CalculatorVersion, SpecVersion: "3.1", Result: domain.ValidationValid,
				Base: 9.8, Temporal: 9.0, HasTemporal: true, Stated: domain.StatedEqual, ValidatedAt: at},
			"r2": {RatingID: "r2", CalculatorVersion: domain.CalculatorVersion, Result: domain.ValidationUnsupported, Reason: "no calculator"},
		},
		Groupings: map[string]domain.Grouping{"s": {{RatingID: "r1", IdentityKey: "k", Linked: true}}},
	}
	srv := ratingsServer(t, repo, app.NewRatingService(snapStore{snap: snap}, nilIDs{}, feedClock{}))
	resp, out := getRatings(t, srv, string(card.ID()))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if out.Cve != "CVE-2024-1" || len(out.Observations) != 2 || len(out.Ratings) != 2 {
		t.Fatalf("body: %+v", out)
	}
	o := out.Observations[0]
	if o.UpdatedAt == nil || o.UpdatedAt.Interpretation == nil || *o.UpdatedAt.Interpretation != gen.ZoneAssumedUtc || o.Revision == nil ||
		out.Observations[1].UpdatedAt != nil {
		t.Errorf("observation: %+v", o)
	}
	r1, r2 := out.Ratings[0], out.Ratings[1]
	if r1.Status != gen.SourceRatingStatusSuperseded || r1.StatusEvent == nil || *r1.StatusEvent.ReplacedBy != "r3" ||
		r1.Validation == nil || *r1.Validation.BaseScore != 9.8 || r1.Validation.TemporalScore == nil ||
		r1.Identity == nil || !*r1.Identity.Linked || *r1.EffectiveContext != "cpe:x" || *r1.StatedScore != 9.8 {
		t.Errorf("r1: %+v", r1)
	}
	if r2.Status != gen.SourceRatingStatusActive || r2.Validation.BaseScore != nil || r2.Validation.StatedComparison != nil ||
		r2.Identity != nil || r2.StatedScore != nil {
		t.Errorf("r2: %+v", r2)
	}
}

func TestGetFaultlineRatingsRefusals(t *testing.T) {
	card := sampleCard(t)
	if resp, _ := getRatings(t, ratingsServer(t, fakeRepo{card: card, found: true}, nil), string(card.ID())); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("not wired: %d", resp.StatusCode)
	}
	ok := app.NewRatingService(snapStore{}, nilIDs{}, feedClock{})
	if resp, _ := getRatings(t, ratingsServer(t, fakeRepo{}, ok), "missing"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing: %d", resp.StatusCode)
	}
	if resp, _ := getRatings(t, ratingsServer(t, fakeRepo{err: errors.New("db")}, ok), "x"); resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("repo error: %d", resp.StatusCode)
	}
	failing := app.NewRatingService(snapStore{err: errors.New("db")}, nilIDs{}, feedClock{})
	if resp, _ := getRatings(t, ratingsServer(t, fakeRepo{card: card, found: true}, failing), string(card.ID())); resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("ratings error: %d", resp.StatusCode)
	}
}
