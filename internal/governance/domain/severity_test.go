package domain

import (
	"errors"
	"testing"
	"time"
)

func f64(v float64) *float64 { return &v }

func TestParseSeverityLevel(t *testing.T) {
	for _, in := range []string{"none", "Low", " MEDIUM ", "high", "critical"} {
		if _, err := ParseSeverityLevel(in); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
	}
	if _, err := ParseSeverityLevel("severe"); !errors.Is(err, ErrOwnerSeverityLevel) {
		t.Fatalf("unknown level: got %v", err)
	}
}

func TestScoreForLevelMovesTheOriginalIntoTheBandByTheShortestWay(t *testing.T) {
	cases := []struct {
		level    SeverityLevel
		original *float64
		want     float64
	}{
		{SeverityMedium, f64(9.8), 6.9}, // above the band: its top
		{SeverityHigh, f64(5.3), 7.0},   // below the band: its bottom
		{SeverityHigh, f64(7.5), 7.5},   // inside: stays
		{SeverityCritical, f64(9.0), 9.0},
		{SeverityLow, f64(0), 0.1},
		{SeverityLow, f64(10), 3.9},
		{SeverityNone, f64(9.8), 0},
		{SeverityCritical, nil, 9.0}, // no original: the bottom of the band
		{SeverityNone, nil, 0},
	}
	for _, c := range cases {
		if got := ScoreForLevel(c.level, c.original); got != c.want {
			t.Errorf("%s from %v: got %v, want %v", c.level, c.original, got, c.want)
		}
	}
}

func TestNewOwnerSeverityByLevel(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.FixedZone("x", 3600))
	who := Actor{Kind: ActorHuman, ID: "analyst-1"}
	o, err := NewOwnerSeverity("Medium", "", f64(9.8), " not reachable in this product ", who, now)
	if err != nil {
		t.Fatal(err)
	}
	if o.Kind != OwnerSeverityByLevel || o.Level != SeverityMedium || o.Score != 6.9 || o.Vector != "" {
		t.Fatalf("got %+v", o)
	}
	if o.Reason != "not reachable in this product" || o.Actor != who || !o.SetAt.Equal(now) || o.SetAt.Location() != time.UTC {
		t.Fatalf("got %+v", o)
	}
	if o.OriginalScore == nil || *o.OriginalScore != 9.8 {
		t.Fatalf("original not kept: %+v", o.OriginalScore)
	}
	if o.BaseScore() != 69 || o.SLABucket() != SLABucketMedium {
		t.Fatalf("base %d bucket %q", o.BaseScore(), o.SLABucket())
	}
}

func TestNewOwnerSeverityByVector(t *testing.T) {
	who := Actor{Kind: ActorHuman, ID: "analyst-1"}
	o, err := NewOwnerSeverity("", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", f64(9.8), "needs a login here", who, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if o.Kind != OwnerSeverityByVector || o.Score != 8.1 || o.Level != SeverityHigh {
		t.Fatalf("got %+v", o)
	}
	if o.Vector != "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" {
		t.Fatalf("vector %q", o.Vector)
	}
	if o.BaseScore() != 81 || o.SLABucket() != SLABucketHigh {
		t.Fatalf("base %d bucket %q", o.BaseScore(), o.SLABucket())
	}
}

func TestOwnerSeverityNoneHasNoDeadlineBucket(t *testing.T) {
	o, err := ComputeOwnerScore("none", "", f64(7.5))
	if err != nil {
		t.Fatal(err)
	}
	if o.Score != 0 || o.BaseScore() != 0 || o.SLABucket() != "" {
		t.Fatalf("got %+v", o)
	}
}

func TestNewOwnerSeverityRefusals(t *testing.T) {
	who := Actor{Kind: ActorHuman, ID: "analyst-1"}
	now := time.Now()
	vec := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	cases := []struct {
		name          string
		level, vector string
		reason        string
		actor         Actor
		at            time.Time
		want          error
	}{
		{"neither", "", "", "r", who, now, ErrOwnerSeverityInput},
		{"both", "low", vec, "r", who, now, ErrOwnerSeverityInput},
		{"bad level", "severe", "", "r", who, now, ErrOwnerSeverityLevel},
		{"bad vector", "", "CVSS:4.0/AV:N", "r", who, now, ErrOwnerSeverityVector},
		{"no reason", "low", "", "  ", who, now, ErrOwnerSeverityReason},
		{"not a person", "low", "", "r", Actor{Kind: ActorPolicy, ID: "p"}, now, ErrOwnerSeverityActor},
		{"no name", "low", "", "r", Actor{Kind: ActorHuman, ID: " "}, now, ErrOwnerSeverityActor},
		{"zero time", "low", "", "r", who, time.Time{}, errZeroTime},
	}
	for _, c := range cases {
		if _, err := NewOwnerSeverity(c.level, c.vector, nil, c.reason, c.actor, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestOwnerSeverityForAnotherFinding(t *testing.T) {
	who := Actor{Kind: ActorHuman, ID: "analyst-1"}
	src, err := NewOwnerSeverity("high", "", f64(9.8), "r", who, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A level is computed again from the other Finding's own original score.
	got := src.For("f-source", f64(5.0))
	if got.Score != 7.0 || got.PickedFrom != "f-source" || *got.OriginalScore != 5.0 || got.Reason != "r" || got.Actor != who {
		t.Fatalf("got %+v", got)
	}
	if src.Score != 8.9 || src.PickedFrom != "" {
		t.Fatalf("source changed: %+v", src)
	}
	if none := src.For("f-source", nil); none.OriginalScore != nil || none.Score != 7.0 {
		t.Fatalf("got %+v", none)
	}
	// A vector's score does not depend on the other Finding's original.
	vec, err := NewOwnerSeverity("", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", f64(9.8), "r", who, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := vec.For("f-source", f64(2.0)); got.Score != 8.1 || got.Vector != vec.Vector {
		t.Fatalf("got %+v", got)
	}
}
