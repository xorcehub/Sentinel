package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"sentinel/internal/allowlist"
	"sentinel/internal/event"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/rules"
	"sentinel/internal/sigmaeval"
	"sentinel/internal/snapshot"
)

// These tests pin the A.3 wiring: the snapshot capture hook in handleEvent is
// purely additive — it calls ShouldCapture + non-blocking Submit BEFORE
// Evaluate, so a saturated capture path can never block or drop a detection.

// snapAllowlistJSONC: a file_capture pattern matching Cursor's Temp\ps-script-
// bootstrap scripts, plus a dev_tool_paths entry so the inline NET-ish rule
// below has an except to exercise (optional). Minimal and self-contained.
const snapAllowlistJSONC = `{
  "file_capture": { "patterns": ["\\\\temp\\\\ps-script-"] }
}`

// snapRuleYAML: fires on powershell -ExecutionPolicy Bypass (EID 1). This is the
// DETECTION carrier — distinct from the EID-11 capture events, which fire no
// rule (so capture-count and hit-count are cleanly separable in the asserts).
const snapRuleYAML = `
title: powershell bypass execution
id: deadbeef-aaaa-0000-0000-000000000001
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-ExecutionPolicy Bypass'
  condition: selection
level: high
x-sentinel: { id: EXEC-TEST-001, severity: critical }
`

func newSnapEngine(t *testing.T) *rules.Engine {
	t.Helper()
	al, err := allowlist.Compile([]byte(snapAllowlistJSONC))
	if err != nil {
		t.Fatalf("allowlist Compile: %v", err)
	}
	rs, err := sigmaeval.Load([]byte(snapRuleYAML))
	if err != nil {
		t.Fatalf("sigmaeval Load: %v", err)
	}
	eng, err := rules.New(rs, al, newFakeDedup())
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	return eng
}

// TestSnapshotFloodDoesNotBlockDetection is the architectural guarantee: with
// the snapshot worker NOT draining (so its 256-slot buffer saturates and Submit
// starts dropping), flooding capture-matching EID-11 events must NOT prevent
// Evaluate from running on every event. The interleaved EID-1 detection events
// must ALL produce hits. This fails if the capture hook ever blocks or if it's
// wired between receive and evaluate in a way that can drop detection.
func TestSnapshotFloodDoesNotBlockDetection(t *testing.T) {
	eng := newSnapEngine(t)
	vault := t.TempDir()
	snap, err := snapshot.New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("snapshot New: %v", err)
	}
	// deliberately do NOT start snap.Run — the buffer will saturate, proving
	// Submit's non-blocking contract under load (drops, never blocks).

	// Build the event stream: 300 capture-matching EID-11 events interleaved
	// with 5 distinct EID-1 detection events. Distinct cmdlines so the dedup
	// window (15m default) doesn't collapse the hits.
	const nCapture = 300
	const nDetect = 5
	events := make([]event.Event, 0, nCapture+nDetect)
	for i := 0; i < nCapture; i++ {
		// capture-matching: EID 11 + path matching \temp\ps-script-. Fires no
		// rule (the rule is EID 1), so these exercise ONLY the capture path.
		events = append(events, event.Event{
			EID:        11,
			RecordID:   uint64(i + 1),
			TargetFile: fmt.Sprintf(`C:\Users\jurij\AppData\Local\Temp\ps-script-%d.ps1`, i),
			Image:      `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		})
	}
	for i := 0; i < nDetect; i++ {
		// detection carrier: EID 1 + bypass. Distinct -File path per event so
		// the target_key (RuleID|Image|CmdLine) differs and dedup lets each fire.
		events = append(events, event.Event{
			EID:      1,
			RecordID: uint64(nCapture + i + 1),
			Image:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine:  fmt.Sprintf(`powershell.exe -ExecutionPolicy Bypass -File C:\Temp\ev-%d.ps1`, i),
		})
	}

	var hits atomic.Uint64
	var buf strings.Builder
	a, err := New(Options{
		Logger:   slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Ingester: mock.New(events...),
		Engine:   eng,
		Snapshot: snap,
		OnHit:    func(event.Hit) { hits.Add(1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// THE guarantee: every detection event fired, despite the capture path
	// being saturated and dropping.
	if got := hits.Load(); got != nDetect {
		t.Errorf("hits = %d, want %d — a saturated capture path must not drop detections\nlog:\n%s",
			got, nDetect, buf.String())
	}
	// Submit was non-blocking: the 300 capture events overflowed the 256 buffer,
	// so some were dropped (not blocked on).
	if snap.Dropped() == 0 {
		t.Errorf("expected Dropped > 0 (buffer should have saturated); got 0 — Submit may be blocking")
	}
	// Capture was actually attempted (ShouldCapture matched + Submit called):
	// the first 256 events are sitting in the buffer (worker never ran).
	if snap.Captured() != 0 {
		t.Errorf("worker never started, so nothing should be captured yet; got %d", snap.Captured())
	}
	// clean up the buffer (Close without a worker is safe — just closes the chan)
	snap.Close()
}

// TestSnapshotWiringCapturesAndDetects is the happy-path wiring check: with the
// worker running, a capture-matching EID 11 AND a detection EID 1 in the same
// batch both land — the file is snapshotted (lost-race here, since the path
// doesn't exist) AND the hit fires. Proves the hook is wired to both paths.
func TestSnapshotWiringCapturesAndDetects(t *testing.T) {
	eng := newSnapEngine(t)
	vault := t.TempDir()
	snap, err := snapshot.New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("snapshot New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { snap.Run(ctx); close(done) }()
	defer func() { snap.Close(); <-done }()

	capEv := event.Event{
		EID:        11,
		RecordID:   1,
		TargetFile: `C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef.ps1`,
		Image:      `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	}
	detEv := event.Event{
		EID:      1,
		RecordID: 2,
		Image:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine:  `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\probe.ps1`,
	}

	var hits atomic.Uint64
	a, err := New(Options{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Ingester: mock.New(capEv, detEv),
		Engine:   eng,
		Snapshot: snap,
		OnHit:    func(event.Hit) { hits.Add(1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	snap.Wait() // ensure the capture worker processed the request

	if got := hits.Load(); got != 1 {
		t.Errorf("detection hit = %d, want 1 (the EID-1 bypass event)", got)
	}
	// The capture file didn't exist on disk, so it's a lost-race — but the
	// manifest was still written, proving ShouldCapture matched + Submit ran.
	if snap.LostRace() != 1 {
		t.Errorf("lostRace = %d, want 1 (capture attempted on the non-existent ps-script)", snap.LostRace())
	}
	// and a manifest was written for it
	matches, _ := filepath.Glob(filepath.Join(vault, "*", "manifest.json"))
	if len(matches) != 1 {
		t.Errorf("expected 1 capture manifest, got %d", len(matches))
	}
}

// TestSnapshotDisabledByDefault asserts a nil Snapshotter (the default, when
// --snapshot-dir is empty) is a clean no-op: events flow through handleEvent
// without any capture attempt, and detection works normally.
func TestSnapshotDisabledByDefault(t *testing.T) {
	eng := newSnapEngine(t)
	detEv := event.Event{
		EID:     1,
		RecordID: 1,
		Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine: `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\x.ps1`,
	}
	var hits atomic.Uint64
	a, err := New(Options{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Ingester: mock.New(detEv),
		Engine:   eng,
		Snapshot: nil, // disabled — the default
		OnHit:    func(event.Hit) { hits.Add(1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("with snapshot disabled, detection should still fire; hits=%d want 1", got)
	}
}
