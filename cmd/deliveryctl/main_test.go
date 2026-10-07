package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
)

// fakeOps stands in for the Communication store: the commands are exercised over the same
// seam they use in production, without a database.
type fakeOps struct {
	dead     []app.Intent
	retried  []string
	canceled []string
	err      error
	since    time.Time
	limit    int
	closed   bool
}

func (f *fakeOps) ListDeadLetters(_ context.Context, since time.Time, limit int) ([]app.Intent, error) {
	f.since, f.limit = since, limit
	return f.dead, f.err
}

func (f *fakeOps) RetryIntent(_ context.Context, id string) error {
	f.retried = append(f.retried, id)
	return f.err
}

func (f *fakeOps) CancelIntent(_ context.Context, id string) error {
	f.canceled = append(f.canceled, id)
	return f.err
}

func (f *fakeOps) opener() opener {
	return func() (intentOps, func(), error) { return f, func() { f.closed = true }, nil }
}

func failingOpener(err error) opener {
	return func() (intentOps, func(), error) { return nil, nil, err }
}

func exec(t *testing.T, cmd string, args []string, open opener) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(cmd, args, &o, &e, open)
	return code, o.String(), e.String()
}

func TestListDeadLetters(t *testing.T) {
	ops := &fakeOps{dead: []app.Intent{{
		ID: "int-1", Type: app.IntentJiraIssue, Destination: "themis-remediation",
		State: app.IntentDeadLetter, Attempts: 3, LastError: "jira down",
	}}}
	code, out, _ := exec(t, "list-deadletters", []string{"--limit", "5", "--since", "1h"}, ops.opener())
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	for _, want := range []string{"INTENT", "int-1", "jira_issue", "themis-remediation", "jira down"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if ops.limit != 5 {
		t.Errorf("limit = %d, want 5", ops.limit)
	}
	if d := time.Since(ops.since); d < 55*time.Minute || d > 65*time.Minute {
		t.Errorf("since = %s, want about an hour ago", ops.since)
	}
	if !ops.closed {
		t.Error("the store was not closed")
	}
}

func TestListDeadLettersEmptyAndDefaults(t *testing.T) {
	ops := &fakeOps{}
	code, out, _ := exec(t, "list-deadletters", nil, ops.opener())
	if code != 0 || !strings.Contains(out, "no dead-lettered") {
		t.Errorf("exit = %d out = %q", code, out)
	}
	if ops.limit != 50 {
		t.Errorf("default limit = %d, want 50", ops.limit)
	}
}

func TestListDeadLettersFailures(t *testing.T) {
	cases := []struct {
		name string
		args []string
		open opener
		want int
	}{
		{"bad flag", []string{"--nope"}, (&fakeOps{}).opener(), 2},
		{"non-positive limit", []string{"--limit", "0"}, (&fakeOps{}).opener(), 2},
		{"store unavailable", nil, failingOpener(errors.New("no dsn")), 1},
		{"query failed", nil, (&fakeOps{err: errors.New("db down")}).opener(), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, _ := exec(t, "list-deadletters", tc.args, tc.open); code != tc.want {
				t.Errorf("exit = %d, want %d", code, tc.want)
			}
		})
	}
}

func TestRetryAndCancel(t *testing.T) {
	ops := &fakeOps{}
	code, out, _ := exec(t, "retry", []string{"--id", "int-1"}, ops.opener())
	if code != 0 || !strings.Contains(out, "reset to pending") {
		t.Errorf("retry: exit = %d out = %q", code, out)
	}
	if len(ops.retried) != 1 || ops.retried[0] != "int-1" {
		t.Errorf("retried = %v", ops.retried)
	}

	code, out, _ = exec(t, "cancel", []string{"--id", "int-2"}, ops.opener())
	if code != 0 || !strings.Contains(out, "cancelled") {
		t.Errorf("cancel: exit = %d out = %q", code, out)
	}
	if len(ops.canceled) != 1 || ops.canceled[0] != "int-2" {
		t.Errorf("canceled = %v", ops.canceled)
	}
}

// An id that names nothing actionable — unknown, or already delivered — must not read as
// success: an operator who typed the wrong id has to be told.
func TestRetryAndCancelOnAnInvalidIDExitNonZero(t *testing.T) {
	for _, cmd := range []string{"retry", "cancel"} {
		t.Run(cmd, func(t *testing.T) {
			ops := &fakeOps{err: app.ErrIntentNotFound}
			code, out, errOut := exec(t, cmd, []string{"--id", "ghost"}, ops.opener())
			if code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
			if out != "" {
				t.Errorf("nothing may be reported as done: %q", out)
			}
			if !strings.Contains(errOut, "no actionable delivery intent") {
				t.Errorf("stderr = %q", errOut)
			}
		})
	}
}

func TestMutateFailures(t *testing.T) {
	cases := []struct {
		name string
		args []string
		open opener
		want int
	}{
		{"missing id", nil, (&fakeOps{}).opener(), 2},
		{"bad flag", []string{"--nope"}, (&fakeOps{}).opener(), 2},
		{"store unavailable", []string{"--id", "int-1"}, failingOpener(errors.New("no dsn")), 1},
		{"store failed", []string{"--id", "int-1"}, (&fakeOps{err: errors.New("db down")}).opener(), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, _ := exec(t, "retry", tc.args, tc.open); code != tc.want {
				t.Errorf("exit = %d, want %d", code, tc.want)
			}
		})
	}
}

func TestUnknownCommandPrintsUsage(t *testing.T) {
	code, _, errOut := exec(t, "deliver-everything", nil, (&fakeOps{}).opener())
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	for _, want := range []string{"list-deadletters", "retry", "cancel", "THEMIS_DATABASE_DSN"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("usage missing %q:\n%s", want, errOut)
		}
	}
}

// Without a DSN the CLI refuses rather than connecting to a default somewhere.
func TestOpenStoreRequiresADSN(t *testing.T) {
	t.Setenv("THEMIS_DATABASE_DSN", "")
	if _, _, err := openStore(); err == nil {
		t.Error("want an error without THEMIS_DATABASE_DSN")
	}
}
