package app

import (
	"bytes"
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

	"sentinel/internal/alert"
	"sentinel/internal/baseline"
	"sentinel/internal/event"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/rules"
	"sentinel/internal/sigmaeval"
	"sentinel/internal/state"
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

// --- Phase 3d: baseline diff routing (Option A: alert once) ---

// BASE-001 in Sigma form (matches rules.d/baseline.yml) — fires on any baseline
// pseudo-event. Used by the routing test below.
const baselineRuleYAML = `
title: New persistence surface entry not in clean baseline
id: 900bd68a-3e18-5491-a608-dd6858f7c7f9
logsource: { product: sentinel-baseline }
detection:
  selection:
    Source: baseline
  condition: selection
level: medium
x-sentinel: { id: BASE-001, severity: suspicious }
`

// TestBaselineAlertOnceRoutesAndDedups is the headline Phase 3d test: a NEW
// persistence entry routes through the engine and fires BASE-001 exactly once;
// a second scan of the same entry stays quiet (Option A); after the alerted set
// is reset (operator re-snapshotted the clean baseline), it fires again.
func TestBaselineAlertOnceRoutesAndDedups(t *testing.T) {
	rs, err := sigmaeval.Load([]byte(baselineRuleYAML))
	if err != nil {
		t.Fatalf("sigmaeval Load: %v", err)
	}
	// Realistic engine dedup (newFakeDedup: real 15-min ReAlert). This test runs
	// all three scans within milliseconds, so WITHOUT the engine's baseline-
	// bypass, scan 3 (post-reset) would be suppressed as dedup-window and hits
	// would stay 1. Passing with the real dedup PINS the bypass: baseline events
	// are deduped solely by the Option-A gate, never by the engine time-window.
	eng, err := rules.New(rs, nil, newFakeDedup())
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}

	// Real state (bbolt, temp) for the alert-once set.
	st, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer st.Close()

	var hits atomic.Uint64
	a, err := New(Options{
		Logger:   discardLogger(),
		Ingester: mock.New(), // empty; we drive baseline routing directly
		Engine:   eng,
		OnHit:    func(event.Hit) { hits.Add(1) },
		Baseline: BaselineConfig{Enabled: true, State: st},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const runKey = `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
	clean := baseline.Snapshot{Entries: []baseline.Entry{
		{Location: runKey, Entry: "A"},
	}}
	dailyWithEvil := baseline.Snapshot{Entries: []baseline.Entry{
		{Location: runKey, Entry: "A"},
		{Location: runKey, Entry: "Evil", Launch: `C:\ProgramData\evil.exe`},
	}}

	// Scan 1: Evil is NEW and un-alerted → routed, BASE-001 fires once.
	newN, fired := a.routeBaselineDiff(clean, dailyWithEvil)
	if newN != 1 || fired != 1 {
		t.Fatalf("scan 1: new=%d fired=%d, want 1/1", newN, fired)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("scan 1: hits=%d want 1", got)
	}

	// Scan 2: Evil still NEW vs clean, but already alerted → Option A: quiet.
	newN2, fired2 := a.routeBaselineDiff(clean, dailyWithEvil)
	if newN2 != 1 || fired2 != 0 {
		t.Fatalf("scan 2: new=%d fired=%d, want 1/0 (Option A suppresses repeat)", newN2, fired2)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("scan 2: hits=%d want 1 (no new alert)", got)
	}

	// Operator re-snapshots the clean baseline → reset clears the alerted set,
	// so the same Evil (still absent from clean) fires again on the next scan.
	if err := st.ResetBaselineAlerted(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	newN3, fired3 := a.routeBaselineDiff(clean, dailyWithEvil)
	if newN3 != 1 || fired3 != 1 {
		t.Fatalf("scan 3 post-reset: new=%d fired=%d, want 1/1 (reset re-enables)", newN3, fired3)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("scan 3: hits=%d want 2 (Evil re-alerted after reset)", got)
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

// TestHitIDCorrelatesLogsAndAlerts is the end-to-end correlation guarantee: the
// hid stamped on a Hit must appear BOTH in the structured-log msg=HIT line AND
// in the ALERTS.log block, so the two logs join on an exact token match instead
// of a colliding timestamp. Uses OnHit (which receives the fully-stamped Hit,
// including h.ID set by buildHit) to drive the same Hit through a LogAlerter,
// mirroring how the real dispatcher writes ALERTS.log.
func TestHitIDCorrelatesLogsAndAlerts(t *testing.T) {
	eng := newTestEngine(t) // nil allowlist -> nothing suppressed; hits pass through

	var slogBuf bytes.Buffer
	var alertsBuf bytes.Buffer
	la := alert.NewLogAlerterTo(&alertsBuf)

	app, err := New(Options{
		Logger:   slog.New(slog.NewTextHandler(&slogBuf, nil)),
		Ingester: mock.New(event.Event{EID: 1, Image: `C:\Windows\System32\conhost.exe`, CmdLine: `conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\x.ps1"`}),
		Engine:   eng,
		OnHit:    func(h event.Hit) { _ = la.Alert(h) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if app.Hits() == 0 {
		t.Fatal("expected at least one hit")
	}

	slogOut := slogBuf.String()
	alertsOut := alertsBuf.String()

	// Extract the hid token from the msg=HIT line.
	hidLine := ""
	for _, line := range strings.Split(slogOut, "\n") {
		if strings.Contains(line, "msg=HIT") {
			hidLine = line
			break
		}
	}
	if hidLine == "" {
		t.Fatalf("no msg=HIT line in structured log:\n%s", slogOut)
	}
	hid := extractKV(hidLine, "hid=")
	if hid == "" {
		t.Fatalf("msg=HIT line has no hid= token:\n%s", hidLine)
	}
	if !strings.HasPrefix(hid, "R-") {
		t.Errorf("hid %q should start with R-", hid)
	}
	// The SAME hid must appear in the ALERTS.log block.
	if !strings.Contains(alertsOut, "hid="+hid) {
		t.Errorf("hid %q from msg=HIT not found in ALERTS.log block:\n%s", hid, alertsOut)
	}
}

// extractKV pulls the value of key (e.g. "hid=") from a slog text line up to
// the next space. Returns "" if absent.
func extractKV(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
