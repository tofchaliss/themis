package notify

import "testing"

func TestRecordWithNilRecorder(t *testing.T) {
	recordWith(nil, "email", "success")
}

func TestRecordWithRecorder(t *testing.T) {
	var gotChannel, gotStatus string
	recordWith(func(channel, status string) {
		gotChannel = channel
		gotStatus = status
	}, "teams", "retried")
	if gotChannel != "teams" || gotStatus != "retried" {
		t.Fatalf("channel=%s status=%s", gotChannel, gotStatus)
	}
}
