package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinel/internal/event"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/rules"
	"sentinel/internal/sigmaeval"
)

// A minimal in-memory Deduper satisfying rules.Deduper (avoids bbolt here so the
// app test stays pure-logic; state.State implements the same interface for prod).
type fakeDedup struct {
	mu   sync.Mutex
	max  uint64
	last map[string]time.Time
}

func newFakeDedup() *fakeDedup { return &fakeDedup{last: map[string]time.Time{}} }
func (d *fakeDedup) SweepSeen(id uint64) bool {
	d.mu.Lock(); defer d.mu.Unlock()
	return id > 0 && id <= d.max
}
func (d *fakeDedup) MarkSeen(id uint64) {
	d.mu.Lock(); defer d.mu.Unlock()
	if id > d.max {
		d.max = id
	}
}
func (d *fakeDedup) ReAlert(ruleID, tk string, win time.Duration) bool {
	d.mu.Lock(); defer d.mu.Unlock()
	k := ruleID + "|" + tk
	now := time.Now()
	if t, ok := d.last[k]; ok && now.Sub(t) < win {
		return false
	}
	d.last[k] = now
	return true
}

// Two rules: an incident one (EXEC-002 headless PS) and a benign one (whoami).
const ruleYAML = `
title: conhost headless powershell
id: f456f516-ed43-5fb4-a7f8-e9d76fcacac1
detection:
  selection:
    EventID: 1
    Image|endswith: '\conhost.exe'
    CommandLine|contains|all: ['--headless','powershell']
  condition: selection
level: high
x-sentinel: { id: EXEC-002, severity: critical }
---
title: whoami exec
id: 33333333-3333-3333-3333-333333333333
detection:
  selection:
    EventID: 1
    Image|endswith: '\whoami.exe'
  condition: selection
level: medium
x-sentinel: { id: EXEC-006, severity: suspicious }
`

func newTestEngine(t *testing.T) *rules.Engine {
	t.Helper()
	rs, err := sigmaeval.Load([]byte(ruleYAML))
	if err != nil {
		t.Fatalf("sigmaeval Load: %v", err)
	}
	// no allowlist (nil) — nothing suppressed; engine handles nil Allowlist.
	eng, err := rules.New(rs, nil, newFakeDedup())
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	return eng
}

func TestRunDrainsEventsAndFiresRules(t *testing.T) {
	eng := newTestEngine(t)
	var hitCount atomic.Uint64
	var seenCount atomic.Uint64

	events := []event.Event{
		// incident vector
		{EID: 1, Image: `C:\Windows\System32\conhost.exe`,
			CmdLine: `conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\x.ps1"`},
		// benign — no rule matches
		{EID: 1, Image: `C:\Windows\System32\cmd.exe`, CmdLine: `cmd /c dir`},
		// whoami -> EXEC-006 suspicious
		{EID: 1, Image: `C:\Windows\System32\whoami.exe`, CmdLine: `whoami`},
	}
	app, err := New(Options{
		Logger:   discardLogger(),
		Ingester: mock.New(events...),
		Engine:   eng,
		OnHit:    func(event.Hit) { hitCount.Add(1) },
		OnEvent:  func(event.Event) { seenCount.Add(1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// mock closes its channel after replay, so Run returns nil on completion.
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := app.EventsSeen(); got != 3 {
		t.Errorf("EventsSeen=%d want 3", got)
	}
	if got := seenCount.Load(); got != 3 {
		t.Errorf("OnEvent called %d times, want 3", got)
	}
	// 2 hits: EXEC-002 (incident) + EXEC-006 (whoami)
	if got := app.Hits(); got != 2 {
		t.Errorf("Hits=%d want 2", got)
	}
	if got := hitCount.Load(); got != 2 {
		t.Errorf("OnHit called %d times, want 2", got)
	}
	if got := app.Suppressed(); got != 0 {
		t.Errorf("Suppressed=%d want 0 (no allowlist)", got)
	}
}

func TestRunRawPassthroughWithoutEngine(t *testing.T) {
	// No Engine: every event is logged, none produce hits. Phase-1 default mode.
	app, err := New(Options{
		Logger:   discardLogger(),
		Ingester: mock.New(event.Event{EID: 1, Image: `C:\x.exe`}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := app.EventsSeen(); got != 1 {
		t.Errorf("EventsSeen=%d want 1", got)
	}
	if got := app.Hits(); got != 0 {
		t.Errorf("Hits=%d want 0 in raw mode", got)
	}
}

func TestContextCancelStopsRun(t *testing.T) {
	app, err := New(Options{
		Logger:   discardLogger(),
		Ingester: &mock.Ingester{Events: hugeEventStream(), EmitDelay: 5 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	// Run returns ctx.Err() on cancellation (not nil, not hang).
	err = app.Run(ctx)
	if err != context.Canceled {
		t.Errorf("Run err=%v want context.Canceled", err)
	}
	// we should have processed at least some events before cancel
	if app.EventsSeen() == 0 {
		t.Error("expected some events processed before cancellation")
	}
}

func TestHeartbeatWritesFile(t *testing.T) {
	hb := filepath.Join(t.TempDir(), "heartbeat.log")
	app, err := New(Options{
		Logger:            discardLogger(),
		Ingester:          mock.New(event.Event{EID: 1, Image: `C:\x.exe`}),
		HeartbeatPath:     hb,
		HeartbeatInterval: -1, // disable periodic; but final flush on channel-close still writes
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := os.ReadFile(hb)
	if err != nil {
		t.Fatalf("read heartbeat: %v", err)
	}
	if !contains(string(data), "alive") {
		t.Errorf("heartbeat content unexpected: %q", data)
	}
	if !contains(string(data), "events_total=1") {
		t.Errorf("heartbeat should reflect events_total=1: %q", data)
	}
}

func TestNewRequiresLoggerAndIngester(t *testing.T) {
	if _, err := New(Options{Ingester: mock.New()}); err == nil {
		t.Error("expected error for missing Logger")
	}
	if _, err := New(Options{Logger: discardLogger()}); err == nil {
		t.Error("expected error for missing Ingester")
	}
}

// --- helpers ---

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func hugeEventStream() []event.Event {
	out := make([]event.Event, 10000)
	for i := range out {
		out[i] = event.Event{EID: 1, Image: `C:\x.exe`}
	}
	return out
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
