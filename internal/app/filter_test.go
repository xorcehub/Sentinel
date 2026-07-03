package app

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"sentinel/internal/allowlist"
	"sentinel/internal/event"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/rules"
	"sentinel/internal/sigmaeval"
)

// filterAllowlistJSONC: dev_tool_paths lists Cursor (so a NET-like rule's
// image_in_dev_tools except suppresses it), plus the same event_log_filter as
// production (powershell eid=11 empty cmdline; git poller). Inline so the test
// is self-contained and deterministic.
const filterAllowlistJSONC = `{
  "dev_tool_paths": { "path": ["\\\\users\\\\[^\\\\]+\\\\appdata\\\\local\\\\programs\\\\cursor\\\\.*\\.exe$"] },
  "event_log_filter": [
    { "eid": 11, "image": "\\\\windowspowershell\\\\v1\\.0\\\\powershell\\.exe$", "cmdline": "^$" },
    { "image": "\\\\git\\\\.*\\\\git\\.exe$", "cmdline": "(check-ignore|rev-parse|--max-count|ls-files)" }
  ]
}`

// captureLogger writes to buf at the DEFAULT level (Info), mirroring the shipped
// production logger so DEBUG dump / DEBUG allowlist-suppression lines are dropped.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

func newEngineWith(t *testing.T, yaml string, al rules.Allowlist) *rules.Engine {
	t.Helper()
	rs, err := sigmaeval.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("sigmaeval Load: %v", err)
	}
	eng, err := rules.New(rs, al, newFakeDedup())
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	return eng
}

// TestFilteredEventStillHits is the no-false-negative guarantee: an event whose
// DEBUG dump line is suppressed by event_log_filter STILL flows through Evaluate
// and fires its HIT. It also confirms the dump is suppressed SELECTIVELY (a
// non-noise sibling event in the same batch is still dumped). If the filter ever
// short-circuited evaluation, hits would be 0.
func TestFilteredEventStillHits(t *testing.T) {
	al, err := allowlist.Compile([]byte(filterAllowlistJSONC))
	if err != nil {
		t.Fatalf("allowlist Compile: %v", err)
	}
	const yaml = `
title: git check-ignore observed
id: deadbeef-0000-0000-0000-000000000001
detection:
  selection:
    EventID: 1
    Image|endswith: '\git.exe'
    CommandLine|contains: 'check-ignore'
  condition: selection
level: medium
x-sentinel: { id: GIT-NOISE-001, severity: suspicious }
`
	eng := newEngineWith(t, yaml, al)

	gitEv := event.Event{EID: 1, Image: `C:\Program Files\Git\mingw64\bin\git.exe`,
		CmdLine: `git.exe check-ignore -v -z --stdin`}
	cmdEv := event.Event{EID: 1, Image: `C:\Windows\System32\cmd.exe`, CmdLine: `cmd /c dir`} // not noise, no rule match

	// Preconditions: the filter classifies exactly as intended.
	if !eng.IsLogNoise(&gitEv) {
		t.Fatal("git poller event must be classified as log noise")
	}
	if eng.IsLogNoise(&cmdEv) {
		t.Fatal("cmd.exe event must NOT be classified as log noise")
	}

	var buf bytes.Buffer
	var hits atomic.Uint64
	a, err := New(Options{
		Logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Ingester: mock.New(gitEv, cmdEv),
		Engine:   eng,
		TraceEvents: true, // dump is now gated; opt in so the selective-filter assertion holds
		OnHit:    func(event.Hit) { hits.Add(1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	log := buf.String()
	// Detection intact despite the dump being suppressed:
	if got := hits.Load(); got != 1 {
		t.Errorf("hits=%d want 1: suppressing the dump must NOT skip evaluation", got)
	}
	if !strings.Contains(log, "msg=HIT") || !strings.Contains(log, "GIT-NOISE-001") {
		t.Errorf("HIT line must still be present:\n%s", log)
	}
	// Dump suppressed SELECTIVELY: only the non-noise event (cmd.exe) is dumped.
	if n := strings.Count(log, "msg=event "); n != 1 {
		t.Errorf("expected exactly 1 per-event dump (cmd.exe only), got %d:\n%s", n, log)
	}
}

// TestSuppressedAllowlistQuietDedupLoud verifies the INFO/DEBUG split for
// suppressions: an allowlist suppression (known-good) is counted but NOT logged
// at the default INFO level, while a dedup-window suppression (real
// rate-limiting of a live hit) still is. Both still increment the counter.
func TestSuppressedAllowlistQuietDedupLoud(t *testing.T) {
	al, err := allowlist.Compile([]byte(filterAllowlistJSONC))
	if err != nil {
		t.Fatalf("allowlist Compile: %v", err)
	}
	const yaml = `
title: outbound from non-dev image
id: deadbeef-0000-0000-0000-000000000002
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
---
title: probe (fired twice to exercise dedup-window)
id: deadbeef-0000-0000-0000-000000000003
detection:
  selection:
    EventID: 1
    Image|endswith: '\probe.exe'
  condition: selection
level: medium
x-sentinel: { id: PROBE-001, severity: suspicious, dedup: 1h }
`
	eng := newEngineWith(t, yaml, al)

	cursorEv := event.Event{EID: 3, Image: `C:\Users\j\AppData\Local\Programs\cursor\Cursor.exe`, DstIP: "203.0.113.9"}
	probeEv := event.Event{EID: 1, Image: `C:\Users\j\probe.exe`, CmdLine: "probe"}

	var buf bytes.Buffer
	a, err := New(Options{
		Logger:   captureLogger(&buf),
		Ingester: mock.New(cursorEv, probeEv, probeEv), // probe twice: HIT then dedup-window
		Engine:   eng,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	log := buf.String()
	// Both suppressions counted (cursor allowlist + probe dedup-window).
	if got := a.Suppressed(); got != 2 {
		t.Errorf("Suppressed=%d want 2 (1 allowlist + 1 dedup-window)", got)
	}
	// cursor / NET-TEST: allowlist-suppressed -> invisible at INFO (DEBUG only).
	if strings.Contains(log, "NET-TEST") {
		t.Errorf("allowlist suppression (NET-TEST) must not surface at INFO:\n%s", log)
	}
	// probe / PROBE-001: dedup-window -> still logged at INFO.
	if !strings.Contains(log, "reason=dedup-window") {
		t.Errorf("dedup-window suppression must still log at INFO:\n%s", log)
	}
}
