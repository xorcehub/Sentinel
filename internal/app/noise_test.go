package app

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"sentinel/internal/allowlist"
	"sentinel/internal/event"
	"sentinel/internal/ingest/mock"
)

// debugLogger captures slog output at DEBUG (so summary/dump lines, which are
// DEBUG, are visible to assertions). *strings.Builder already satisfies
// io.Writer, so no adapter is needed.
func debugLogger(buf *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestEventDumpGatedByTrace proves the per-event DEBUG dump is off by default
// and appears only with TraceEvents. With it off, the log is free of the raw
// passthrough that dominated it (~40% of lines, no detection value).
func TestEventDumpGatedByTrace(t *testing.T) {
	ev := event.Event{EID: 1, Image: `C:\Windows\System32\cmd.exe`, CmdLine: `cmd /c dir`}

	run := func(trace bool) string {
		var buf strings.Builder
		a, err := New(Options{
			Logger:      debugLogger(&buf),
			Ingester:    mock.New(ev),
			TraceEvents: trace,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := a.Run(context.Background()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return buf.String()
	}

	// Off (default): no per-event dump at all.
	if n := strings.Count(run(false), "msg=event "); n != 0 {
		t.Errorf("TraceEvents=false: expected 0 event dumps, got %d", n)
	}
	// On: one event -> one dump line.
	if n := strings.Count(run(true), "msg=event "); n != 1 {
		t.Errorf("TraceEvents=true: expected 1 event dump, got %d", n)
	}
}

// TestAllowlistSuppressionDedupedToSummary is the headline noise fix: an
// already-allowed app tripping the same rule many times must produce ONE
// periodic summary line (with the count), NOT one per-event line each. The
// counter still reflects every suppression, and detection (HITs) is unaffected.
// The summary flushes at drain completion (the mock ingester closes its
// channel after replay), mirroring the shutdown flush in production.
func TestAllowlistSuppressionDedupedToSummary(t *testing.T) {
	al, err := allowlist.Compile([]byte(filterAllowlistJSONC))
	if err != nil {
		t.Fatalf("allowlist Compile: %v", err)
	}
	const yaml = `
title: outbound from non-dev image
id: deadbeef-0000-0000-0000-000000000009
detection:
  selection:
    EventID: 3
    DestinationIp|re: '^[0-9.]+$'
  condition: selection
level: medium
x-sentinel:
  id: NET-TEST
  severity: suspicious
  except:
    image_in_dev_tools: dev_tool_paths
`
	eng := newEngineWith(t, yaml, al)

	// The SAME cursor event fed 5 times: allowlist suppresses all 5 (same rule,
	// same image). Pre-fix this was 5 identical DEBUG lines; post-fix it is one
	// summary line with count=5.
	cursorEv := event.Event{EID: 3, Image: `C:\Users\j\AppData\Local\Programs\cursor\Cursor.exe`, DstIP: "203.0.113.9"}
	feed := make([]event.Event, 5)
	for i := range feed {
		feed[i] = cursorEv
	}

	var buf strings.Builder
	var hits atomic.Uint64
	a, err := New(Options{
		Logger:   debugLogger(&buf),
		Ingester: mock.New(feed...),
		Engine:   eng,
		OnHit:    func(event.Hit) { hits.Add(1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	log := buf.String()
	// Counter reflects ALL five (audit integrity — the heartbeat total depends on it).
	if got := a.Suppressed(); got != 5 {
		t.Errorf("Suppressed=%d want 5 (counter must count every suppression)", got)
	}
	// No HITs: cursor is allowlisted, so nothing fires.
	if got := hits.Load(); got != 0 {
		t.Errorf("hits=%d want 0 (allowlisted app must not fire)", got)
	}
	// Exactly ONE summary line, carrying count=5.
	if n := strings.Count(log, "suppressed (allowlist) summary"); n != 1 {
		t.Errorf("expected 1 summary line, got %d:\n%s", n, log)
	}
	if !strings.Contains(log, "count=5") {
		t.Errorf("summary should report count=5:\n%s", log)
	}
	// ZERO per-event allowlist lines (the old flood form). The exact token
	// msg="suppressed (allowlist)" is NOT a substring of the summary's
	// msg="suppressed (allowlist) summary" (the `)` is followed by a space in
	// the summary, not a quote), so this count is unambiguous.
	if n := strings.Count(log, `msg="suppressed (allowlist)"`); n != 0 {
		t.Errorf("expected 0 per-event allowlist lines, got %d:\n%s", n, log)
	}
}
