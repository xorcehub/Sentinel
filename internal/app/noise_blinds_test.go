package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sentinel/internal/allowlist"
	"sentinel/internal/event"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/rules"
	"sentinel/internal/sigmaeval"
)

// These tests pin the "noise filtering doesn't blind detection" guarantee at
// the APP layer: the per-event dump gate (TraceEvents), the event_log_filter
// (eid=11 powershell), and the allowlist-suppression dedup all sit in the LOG
// path — none may short-circuit Evaluate. They load the REAL catalog + REAL
// allowlist so they catch a future config edit that over-trusts or over-filters.

func appRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// realEngineFromDisk builds an Engine from the shipped rules.d + allowlist.json.
func realEngineFromDisk(t *testing.T) *rules.Engine {
	t.Helper()
	root := appRepoRoot(t)
	dir := filepath.Join(root, "rules.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("rules.d not present (%v); skipping", err)
	}
	var concat []byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		concat = append(concat, b...)
		if len(b) > 0 && b[len(b)-1] != '\n' {
			concat = append(concat, '\n')
		}
		concat = append(concat, "---\n"...)
	}
	rs, err := sigmaeval.Load(concat)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	al, err := allowlist.Load(filepath.Join(root, "config", "allowlist.json"))
	if err != nil {
		t.Skipf("allowlist.json not present (%v); skipping", err)
	}
	eng, err := rules.New(rs, al, newFakeDedup())
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	return eng
}

// TestEID11FilteredPowershellStillDetectsStartupWrite is the precise regression
// for the user's worry: the event_log_filter drops eid=11 powershell events from
// the per-event DEBUG dump (they were ~24k lines/day of noise). This test feeds
// EXACTLY such a filtered event — but one that ALSO writes a .lnk to the Startup
// folder (PERSIST-004). The dump MUST be suppressed (the filter ran) AND the
// PERSIST-004 alert MUST still fire (the filter did NOT blind detection). If
// this fails, the noise filter is dropping events before evaluation.
func TestEID11FilteredPowershellStillDetectsStartupWrite(t *testing.T) {
	eng := realEngineFromDisk(t)

	// This event matches the event_log_filter entry {eid:11, image:powershell,
	// cmdline:"^$"} -> dump suppressed. It ALSO matches PERSIST-004 (eid 11 +
	// Startup + .lnk) -> must HIT. TraceEvents=true so the ONLY reason the dump
	// is absent is IsLogNoise, not the trace gate.
	ev := event.Event{
		EID:         11,
		Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine:     "", // matches the filter's cmdline:"^$" clause
		TargetFile:  `C:\Users\jurij\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.lnk`,
	}

	// Sanity: confirm the real allowlist classifies this as dump-noise.
	if !eng.IsLogNoise(&ev) {
		t.Fatal("precondition: real allowlist should classify eid=11 powershell as log-noise")
	}

	var buf strings.Builder
	var hits int
	a, err := New(Options{
		Logger:      slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Ingester:    mock.New(ev),
		Engine:      eng,
		TraceEvents: true,
		OnHit:       func(event.Hit) { hits++ },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	log := buf.String()
	// Detection survived the filter:
	if hits == 0 {
		t.Errorf("PERSIST-004 must fire despite the eid=11 dump filter; log:\n%s", log)
	}
	if !strings.Contains(log, "PERSIST-004") {
		t.Errorf("expected a PERSIST-004 HIT; log:\n%s", log)
	}
	// The dump was suppressed by IsLogNoise (trace is ON, so absent dump == filter):
	if n := strings.Count(log, "msg=event "); n != 0 {
		t.Errorf("the eid=11 powershell dump should be suppressed by event_log_filter; got %d dump lines:\n%s", n, log)
	}
}

// TestTraceGateOffStillDetects pins that turning the raw dump OFF (the default,
// and the biggest single noise reduction) does not affect evaluation: a
// rule-matching event still produces its HIT with TraceEvents=false.
func TestTraceGateOffStillDetects(t *testing.T) {
	eng := realEngineFromDisk(t)
	ev := event.Event{
		EID:     1,
		Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine: `powershell.exe -ExecutionPolicy Bypass -File C:\Users\jurij\AppData\Local\Temp\evil.ps1`,
	}
	var buf strings.Builder
	var hits int
	a, err := New(Options{
		Logger:      slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Ingester:    mock.New(ev),
		Engine:      eng,
		TraceEvents: false, // default — dump fully off
		OnHit:       func(event.Hit) { hits++ },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	log := buf.String()
	if hits == 0 || !strings.Contains(log, "EXEC-001") {
		t.Errorf("EXEC-001 must fire with TraceEvents=false; log:\n%s", log)
	}
	if strings.Contains(log, "msg=event ") {
		t.Errorf("TraceEvents=false must produce zero event dumps; log:\n%s", log)
	}
}
