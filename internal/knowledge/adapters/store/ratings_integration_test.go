//go:build integration

package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type ratingIDs struct{ n int }

func (r *ratingIDs) NewID() string { r.n++; return fmt.Sprintf("r-%03d", r.n) }

type ratingClock struct{}

func (ratingClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

// TestSourceRatingsLifecycle drives the real RatingService over Postgres: an NVD copy, the vendor
// document, an unchanged re-fetch, a withdrawal, and a change back to the first content.
func TestSourceRatingsLifecycle(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	st := store.New(pool)
	svc := app.NewRatingService(st, &ratingIDs{}, ratingClock{})
	cveID, _ := value.NewCVEID("CVE-2024-1111")
	vec := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U"
	vendor := domain.PublishedRating{Assessor: "redhat", Publisher: "redhat", Version: "3.1", Vector: vec,
		StatedScore: 9.8, HasStatedScore: true, SeverityWord: "Critical"}
	doc := func(rs ...domain.PublishedRating) domain.ObservationInput {
		return domain.ObservationInput{Source: "redhat", Feed: "redhat-hydra", DocumentRef: "redhat:CVE-2024-1111",
			Complete: true, UpdatedAt: domain.ParseSourceTime("2024-01-02T03:04:05"),
			Applicability: []string{"cpe:/o:redhat:enterprise_linux:9"}, Ratings: rs,
			Fetch: domain.FetchMeta{Endpoint: "e", HTTPStatus: 200, ETag: "x"}}
	}
	nvd := domain.ObservationInput{Source: "nvd", DocumentRef: "nvd:CVE-2024-1111", Complete: true,
		Ratings: []domain.PublishedRating{{Assessor: "secalert@redhat.com", NVDType: "Secondary", Version: "3.1", Vector: vec}}}
	for i, in := range []domain.ObservationInput{nvd, doc(vendor), doc(vendor), doc(), doc(vendor)} {
		if err := svc.Record(ctx, cveID, in); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM rating_observations`); n != 4 {
		t.Errorf("observations = %d, want 4 (the re-fetch is a seen event)", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM rating_observation_seen WHERE outcome = 'success_unchanged'`); n != 1 {
		t.Errorf("unchanged seen events = %d, want 1", n)
	}

	view, err := svc.RatingsForCVE(ctx, cveID.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Observations) != 4 || len(view.Ratings) != 3 {
		t.Fatalf("view: %d observations, %d ratings", len(view.Observations), len(view.Ratings))
	}
	o := view.Observations[1]
	if o.UpdatedAt.Interpretation != domain.TimeZoneAssumedUTC || o.UpdatedAt.Original != "2024-01-02T03:04:05" || o.UpdatedAt.Instant.IsZero() ||
		len(o.Applicability) != 1 || !o.Complete {
		t.Errorf("observation: %+v", o)
	}
	nvdPub, first, back := view.Ratings[0], view.Ratings[1], view.Ratings[2]
	if nvdPub.Status != domain.RatingActive || first.Status != domain.RatingStatusWithdrawn || back.Status != domain.RatingActive {
		t.Errorf("statuses: %s %s %s", nvdPub.Status, first.Status, back.Status)
	}
	if first.Event == nil || first.Event.CausedBy == "" || first.Event.SourceTime.Interpretation != domain.TimeZoneAssumedUTC {
		t.Errorf("event: %+v", first.Event)
	}
	if v := first.Validation; v == nil || v.Result != domain.ValidationValid || v.Base != 9.8 || !v.HasTemporal || v.Temporal != 9.0 || v.Stated != domain.StatedEqual {
		t.Errorf("validation: %+v", first.Validation)
	}
	if !first.Rating.HasStatedScore || first.Rating.StatedScore != 9.8 || first.Rating.InheritedContext == "" {
		t.Errorf("rating: %+v", first.Rating)
	}
	if nvdPub.Identity.IdentityKey == "" || nvdPub.Identity.IdentityKey != back.Identity.IdentityKey {
		t.Errorf("the NVD copy and the vendor rating are one identity: %+v / %+v", nvdPub.Identity, back.Identity)
	}

	// A superseding correction records a replaced-by reference.
	corrected := vendor
	corrected.Vector, corrected.StatedScore = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7
	if err := svc.Record(ctx, cveID, doc(corrected)); err != nil {
		t.Fatal(err)
	}
	view, _ = svc.RatingsForCVE(ctx, cveID.String())
	if ev := view.Ratings[2].Event; ev == nil || ev.Kind != domain.RatingSuperseded || ev.ReplacedBy != view.Ratings[3].Rating.ID {
		t.Errorf("superseded: %+v", ev)
	}
	// A CVE with nothing recorded reads empty, not an error.
	empty, err := svc.RatingsForCVE(ctx, "CVE-2000-0001")
	if err != nil || len(empty.Ratings) != 0 || len(empty.Observations) != 0 {
		t.Errorf("empty: %+v %v", empty, err)
	}
}
