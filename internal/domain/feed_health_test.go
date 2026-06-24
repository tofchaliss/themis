package domain

import (
	"context"
	"errors"
	"testing"
)

func TestNopFeedHealthRecorder(t *testing.T) {
	var r FeedHealthRecorder = NopFeedHealthRecorder{}
	if err := r.RecordFeedSuccess(context.Background(), "epss_kev"); err != nil {
		t.Fatalf("success = %v", err)
	}
	if err := r.RecordFeedFailure(context.Background(), "epss_kev", errors.New("boom")); err != nil {
		t.Fatalf("failure = %v", err)
	}
}

func TestFeedHealthRecorderOrNop(t *testing.T) {
	if _, ok := FeedHealthRecorderOrNop(nil).(NopFeedHealthRecorder); !ok {
		t.Fatal("nil → NopFeedHealthRecorder")
	}
	custom := NopFeedHealthRecorder{}
	if got := FeedHealthRecorderOrNop(custom); got != FeedHealthRecorder(custom) {
		t.Fatal("non-nil returned unchanged")
	}
}
