package harness

import (
	"errors"
	"strings"
	"testing"

	"github.com/tofchaliss/themis-ai-runtime/src/harness/state"
)

// HARNESS-COV-1: the replay links judged on hand-built event streams. The forge (refusals_test)
// proves the refusals through the runtime's own handle, which enforces the durability
// constitution and therefore cannot produce a record written by the wrong layer or out of
// order; these tests feed the replay functions the shapes the handle refuses to write, so the
// intake's own rejection of them is exercised rather than assumed.

func ev(seq int64, class, writer, body string, refs ...state.Ref) state.Event {
	return state.Event{Seq: seq, Class: class, Writer: writer, Body: []byte(body), Refs: refs}
}

func TestReplayProduction_Refusals(t *testing.T) {
	egress := state.Ref{ID: "sha256:" + strings.Repeat("aa", 32), Class: state.ObjEgressArtifact}
	bound := func(seq int64, writer string, refs ...state.Ref) state.Event {
		return ev(seq, state.EvArtifact, writer, `{"artifact":"`+egress.ID+`"}`, refs...)
	}
	completed := func(seq int64) state.Event { return ev(seq, state.EvLifecycle, "l6", `{"to":"`+string(state.StatusCompleted)+`"}`) }
	man := &state.Manifest{}
	for _, tc := range []struct {
		name   string
		events []state.Event
		seq    int64
		want   string
	}{
		{"no event at the bound seq", []state.Event{bound(1, "l6", egress)}, 7, "no event at seq 7"},
		{"bound seq is not an artifact event", []state.Event{completed(3)}, 3, "not artifact-bound"},
		{"artifact-bound written by someone else", []state.Event{bound(2, "l5", egress)}, 2, `written by "l5"`},
		{"competing artifact-bound", []state.Event{bound(2, "l6", egress), bound(4, "l6", egress)}, 2, "competing artifact-bound at seq 4"},
		{"no egress reference", []state.Event{bound(2, "l6")}, 2, "exactly one egress-artifact"},
		{"body names another address", []state.Event{ev(2, state.EvArtifact, "l6", `{"artifact":"sha256:other"}`, egress)}, 2, "different address"},
		{"no lifecycle COMPLETED", []state.Event{bound(2, "l6", egress)}, 2, "no lifecycle COMPLETED"},
		{"COMPLETED precedes the binding", []state.Event{completed(1), bound(2, "l6", egress)}, 2, "precedes the binding"},
		{"manifest does not project the artifact", []state.Event{bound(2, "l6", egress), completed(3)}, 2, "manifest does not project"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := replayProduction(nil, man, tc.events, &Resolution{BindingSeq: tc.seq, Tuple: Tuple{TaskID: "fx"}})
			if !errors.Is(err, ErrProvenance) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want provenance refusal containing %q", err, tc.want)
			}
		})
	}
}

func TestReplayL5_Refusals(t *testing.T) {
	addr := strings.Repeat("aa", 32)
	tr := func(seq int64, writer, from, to, reason string) state.Event {
		return ev(seq, state.EvL5Transition, writer, `{"From":"`+from+`","To":"`+to+`","Reason":"`+reason+`"}`)
	}
	op := func(seq int64, writer, outcome, address string) state.Event {
		return ev(seq, state.EvL5Op, writer, `{"op":"egress","outcome":"`+outcome+`","artifact_address":"`+address+`"}`)
	}
	res := func() *Resolution { return &Resolution{BindingSeq: 10, ArtifactObjectID: "sha256:" + addr} }
	for _, tc := range []struct {
		name   string
		events []state.Event
		want   string
	}{
		{"transition written by someone else", []state.Event{tr(1, "l6", "ACTIVE", "SEALED", "task-complete")}, `written by "l6"`},
		{"malformed transition", []state.Event{ev(1, state.EvL5Transition, "l5", `{"From":""}`)}, "malformed l5-transition"},
		{"SEALED from the wrong state", []state.Event{tr(1, "l5", "EGRESSING", "SEALED", "task-complete")}, "not ACTIVE"},
		{"EGRESSING without SEALED", []state.Event{tr(1, "l5", "SEALED", "EGRESSING", "")}, "without a preceding"},
		{"op written by someone else", []state.Event{tr(1, "l5", "ACTIVE", "SEALED", "task-complete"), op(2, "l6", "acknowledged", addr)}, `l5-op at seq 2 written by "l6"`},
		{"egress acknowledged before EGRESSING", []state.Event{tr(1, "l5", "ACTIVE", "SEALED", "task-complete"), op(2, "l5", "acknowledged", addr)}, "precedes EGRESSING"},
		{"missing SEALED", nil, "missing l5-transition ACTIVE→SEALED"},
		{"missing EGRESSING", []state.Event{tr(1, "l5", "ACTIVE", "SEALED", "task-complete")}, "missing l5-transition SEALED→EGRESSING"},
		{"refused egress never satisfies", []state.Event{tr(1, "l5", "ACTIVE", "SEALED", "task-complete"), tr(2, "l5", "SEALED", "EGRESSING", ""), op(3, "l5", "refused", addr)}, "missing l5-op egress witness"},
		{"other op kinds are ignored", []state.Event{tr(1, "l5", "ACTIVE", "SEALED", "task-complete"), tr(2, "l5", "SEALED", "EGRESSING", ""), ev(3, state.EvL5Op, "l5", `{"op":"exec"}`)}, "missing l5-op egress witness"},
		{"events at or after the binding are not read", []state.Event{tr(10, "l5", "ACTIVE", "SEALED", "task-complete")}, "missing l5-transition ACTIVE→SEALED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := replayL5(tc.events, res())
			if !errors.Is(err, ErrProvenance) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want provenance refusal containing %q", err, tc.want)
			}
		})
	}
	// The positive shape, for symmetry: the links land on the resolution.
	r := res()
	if err := replayL5([]state.Event{tr(1, "l5", "ACTIVE", "SEALED", "task-complete"), tr(2, "l5", "SEALED", "EGRESSING", ""), op(3, "l5", "acknowledged", addr)}, r); err != nil {
		t.Fatalf("positive: %v", err)
	}
	if r.L5.SealedSeq != 1 || r.L5.EgressingSeq != 2 || r.L5.EgressOpSeq != 3 || r.L5.EgressAddr != addr {
		t.Fatalf("links = %+v", r.L5)
	}
}

func TestReestablishVerification_OrderAndWriter(t *testing.T) {
	// A verification AFTER the binding with none before it: verification does not correspond to
	// the production it claims to verify.
	err := reestablishVerification(nil, Checkout{}, []state.Event{ev(12, state.EvVerification, "l10", `{}`)}, &Resolution{BindingSeq: 10})
	if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "does not correspond") {
		t.Fatalf("after binding: %v", err)
	}
	// Written by the wrong layer.
	err = reestablishVerification(nil, Checkout{}, []state.Event{ev(3, state.EvVerification, "l6", `{}`)}, &Resolution{BindingSeq: 10})
	if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), `written by "l6"`) {
		t.Fatalf("wrong writer: %v", err)
	}
}

func TestShort(t *testing.T) {
	if short("abc") != "abc" || short(strings.Repeat("x", 20)) != strings.Repeat("x", 12) {
		t.Fatal("short must cut at twelve characters and leave shorter strings alone")
	}
}
