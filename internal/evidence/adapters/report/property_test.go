package report

import (
	"bytes"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// propertyFixtures is one body per report dialect, so every property below is
// exercised against all four conversion paths rather than the convenient one.
func propertyFixtures(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"cortex-csv":  readFixture(t, "cortex", "slice.csv"),
		"cortex-json": readFixture(t, "cortex", "2026-10-05-array.json"),
		"trivy":       readFixture(t, "trivy", "sample.input.json"),
		"curated":     []byte(curatedSample),
		// A body with no derivable timestamp: the error must be deterministic too, or a
		// retry would look like a different fault.
		"cortex-csv-no-observed": readFixture(t, "cortex", "no-observed.csv"),
	}
}

// TestConvertIsPureProperty is D3 as a test rather than a convention: conversion is
// a pure function of (bytes, observedAt). Evidence's dedup key is the SHA-256 of the
// filed bytes, so any impurity — a clock read, a map iteration, a buffer reused
// across calls — files a duplicate scan of the same image and nobody can tell it
// from a real one.
func TestConvertIsPureProperty(t *testing.T) {
	fixtures := propertyFixtures(t)
	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.SampledFrom(sortedKeys(fixtures)).Draw(rt, "dialect")
		observedAt := drawObservedAt(rt)
		body := fixtures[name]

		firstDoc, firstStats, firstErr := Convert(body, observedAt)
		secondDoc, secondStats, secondErr := Convert(body, observedAt)

		switch {
		case (firstErr == nil) != (secondErr == nil):
			rt.Fatalf("%s: one call errored and the other did not: %v / %v", name, firstErr, secondErr)
		case firstErr != nil:
			if firstErr.Error() != secondErr.Error() {
				rt.Fatalf("%s: the refusal is not stable: %q vs %q", name, firstErr, secondErr)
			}
			return
		}
		if !bytes.Equal(firstDoc, secondDoc) {
			rt.Fatalf("%s: the same (bytes, observedAt) produced two documents", name)
		}
		if firstStats != secondStats {
			rt.Fatalf("%s: stats differ across calls: %+v vs %+v", name, firstStats, secondStats)
		}
	})
}

// TestConvertDoesNotMutateTheBodyProperty is the other half of purity: the submitted
// bytes are what gets digested as the source, so a converter that edits its input in
// place would make `source_digest` depend on whether anyone had converted it yet.
func TestConvertDoesNotMutateTheBodyProperty(t *testing.T) {
	fixtures := propertyFixtures(t)
	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.SampledFrom(sortedKeys(fixtures)).Draw(rt, "dialect")
		original := fixtures[name]
		body := append([]byte(nil), original...)
		_, _, _ = Convert(body, drawObservedAt(rt))
		if !bytes.Equal(body, original) {
			rt.Fatalf("%s: Convert mutated the submitted body", name)
		}
	})
}

// TestSuppliedObservedAtReachesTheDocumentProperty: a supplied timestamp is an
// assertion about WHICH observation this is, so two different supplied timestamps
// must produce two different documents — otherwise the second observation dedups
// into the first (tasks.md 7.2).
func TestSuppliedObservedAtReachesTheDocumentProperty(t *testing.T) {
	fixtures := propertyFixtures(t)
	// Pass-through files the submitted bytes verbatim, so the timestamp gates
	// admission without appearing in the output — by design.
	converting := []string{"cortex-csv", "cortex-json", "trivy", "cortex-csv-no-observed"}
	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.SampledFrom(converting).Draw(rt, "dialect")
		body := fixtures[name]
		a := time.Unix(rapid.Int64Range(0, 4_000_000_000).Draw(rt, "a"), 0).UTC()
		b := time.Unix(rapid.Int64Range(0, 4_000_000_000).Draw(rt, "b"), 0).UTC()

		docA, _, errA := Convert(body, a)
		docB, _, errB := Convert(body, b)
		if errA != nil || errB != nil {
			rt.Fatalf("%s: a supplied observed_at must always be usable: %v / %v", name, errA, errB)
		}
		if a.Equal(b) != bytes.Equal(docA, docB) {
			rt.Fatalf("%s: observed_at %s and %s produced %v documents", name, a, b, map[bool]string{true: "one", false: "two"}[bytes.Equal(docA, docB)])
		}
	})
}

// TestDetectNeverPanicsProperty: the border is reached by whatever an operator's
// `curl` sends, and the one thing it may never do is crash the node. 0, 1 and >1
// elements are three cardinalities and 0 is the one that panics (CONVENTIONS R5).
func TestDetectNeverPanicsProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		body := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(rt, "body")
		contentType := rapid.SampledFrom([]string{"", "text/csv", "application/json", "text/csv; charset=utf-8"}).Draw(rt, "contentType")
		kind, dialect, err := Detect(contentType, body)
		if err != nil {
			return
		}
		if kind != KindReport && kind != KindSBOM {
			rt.Fatalf("Detect returned an unknown kind %q", kind)
		}
		if _, ok := ConverterFor(dialect); !ok && kind == KindReport {
			rt.Fatalf("Detect named report dialect %q with no converter", dialect)
		}
		// Whatever it named, converting must refuse rather than panic.
		_, _, _ = Convert(body, time.Unix(0, 0))
	})
}

// drawObservedAt samples the whole observedAt domain the port accepts, including the
// zero value that means "derive from the body".
func drawObservedAt(rt *rapid.T) time.Time {
	if rapid.Bool().Draw(rt, "derive") {
		return time.Time{}
	}
	secs := rapid.Int64Range(0, 4_000_000_000).Draw(rt, "observedAtUnix")
	nanos := rapid.Int64Range(0, 999_999_999).Draw(rt, "observedAtNanos")
	loc := rapid.SampledFrom([]*time.Location{time.UTC, time.FixedZone("plus2", 7200)}).Draw(rt, "zone")
	return time.Unix(secs, nanos).In(loc)
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// rapid.SampledFrom must see a stable slice, so the order cannot come from map
	// iteration — the same hazard this package avoids in its output encoders.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
