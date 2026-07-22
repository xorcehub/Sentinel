package app

import (
	"context"
	"sync/atomic"
	"testing"

	"sentinel/internal/event"
	"sentinel/internal/ingest/mock"
)

// TestRunContainsEventPanic is the safety-property regression: a panic inside
// handleEvent (rule eval, allowlist, OnEvent hook, anything) must skip ONE
// event and continue the drain loop. It must NOT crash the daemon. See
// docs/plan-parsing_2107.md Phase 1 — the SYSTEM daemon runs detection, so a
// crash blinds detection. This test fails if anyone removes the per-event
// recover in App.Run or wraps it incorrectly.
func TestRunContainsEventPanic(t *testing.T) {
	var processedAfterPanic atomic.Uint64

	app, err := New(Options{
		Logger:   discardLogger(), // io.Discard; defined in app_test.go
		Ingester: mock.New(markerPanicEvent, normalEvent),
		// OnEvent fires inside handleEvent; panic here simulates any panic in
		// the handleEvent body (rule eval, allowlist, snapshot capture).
		OnEvent: func(ev event.Event) {
			if ev.Image == "panic-marker.exe" {
				panic("simulated handler panic on attacker-shaped event")
			}
			if ev.Image == "normal.exe" {
				processedAfterPanic.Add(1)
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Run must return nil (mock ingester closes after replay). If the panic
	// was NOT contained, Run either crashes the test process or hangs.
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error after contained panic: %v", err)
	}

	if got := app.PanicsContained(); got != 1 {
		t.Errorf("PanicsContained=%d, want 1 (one panic should have been contained)", got)
	}
	if got := processedAfterPanic.Load(); got != 1 {
		t.Errorf("events processed after the panic = %d, want 1 (drain loop must continue)", got)
	}
	if got := app.EventsSeen(); got != 2 {
		t.Errorf("EventsSeen=%d, want 2 (both events must reach handleEvent)", got)
	}
}

// TestRunContainsRepeatedPanics proves the loop survives a sustained panic
// attack — an adversary who can craft one panic can craft N. The daemon must
// keep processing the non-panicking events in between.
func TestRunContainsRepeatedPanics(t *testing.T) {
	const panicCount = 50
	events := make([]event.Event, 0, panicCount*2)
	for i := 0; i < panicCount; i++ {
		events = append(events, markerPanicEvent, normalEvent)
	}

	app, err := New(Options{
		Logger:   discardLogger(),
		Ingester: mock.New(events...),
		OnEvent: func(ev event.Event) {
			if ev.Image == "panic-marker.exe" {
				panic("sustained panic attack")
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := app.PanicsContained(), uint64(panicCount); got != want {
		t.Errorf("PanicsContained=%d, want %d", got, want)
	}
}

var (
	markerPanicEvent = event.Event{EID: 1, Image: "panic-marker.exe", RecordID: 1}
	normalEvent      = event.Event{EID: 1, Image: "normal.exe", RecordID: 2}
)
