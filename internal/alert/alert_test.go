package alert

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinel/internal/event"
)

// fakeAlerter records every Alert call. Safe for concurrent use.
type fakeAlerter struct {
	name    string
	mu      sync.Mutex
	calls   []event.Hit
	delay   time.Duration // optional, to simulate a slow alerter (popup)
}

func (f *fakeAlerter) Name() string { return f.name }
func (f *fakeAlerter) Alert(h event.Hit) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, h)
	return nil
}
func (f *fakeAlerter) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestLogAlerterFormat(t *testing.T) {
	var buf bytes.Buffer
	la := NewLogAlerterTo(&buf)
	h := event.Hit{
		RuleID:   "PERSIST-001",
		RuleName: "Scheduled task with bypass",
		Severity: event.SevCritical,
		Event: event.Event{
			Image:   `C:\Windows\System32\conhost.exe`,
			CmdLine: `conhost.exe --headless powershell`,
		},
		Matched: "PERSIST-001 on ...",
		AlertTo: []string{"popup", "toast", "log", "eventlog"},
		Time:    time.Date(2026, 6, 26, 14, 3, 11, 0, time.UTC),
	}
	if err := la.Alert(h); err != nil {
		t.Fatalf("Alert: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"CRITICAL", "rule=PERSIST-001", "image : C:\\Windows\\System32\\conhost.exe", "action: popup,toast,log,eventlog"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

// TestLogAlerterShowsNetworkContext is the regression for the pi-lite gap:
// a NET-002 hit must surface the dst IP:port/proto, not just image+cmd. The
// original formatHit hardcoded only those two fields and dropped DstIP/DstPort
// even though they were parsed and carried in Hit.Event.
func TestLogAlerterShowsNetworkContext(t *testing.T) {
	var buf bytes.Buffer
	la := NewLogAlerterTo(&buf)
	h := event.Hit{
		RuleID: "NET-002", RuleName: "Outbound to public host",
		Severity: event.SevSuspicious,
		Event: event.Event{
			EID:     3,
			Image:   `C:\dev\pi-lite.exe`,
			DstIP:   "142.93.4.11",
			DstPort: 443,
			DstProto: "tcp",
		},
		Matched: "NET-002 on ...pi-lite.exe",
		AlertTo: []string{"toast", "log", "eventlog"},
		Time:    time.Date(2026, 6, 29, 12, 54, 54, 0, time.UTC),
	}
	if err := la.Alert(h); err != nil {
		t.Fatalf("Alert: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"dst   : 142.93.4.11:443/tcp", "image :", "rule=NET-002"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

// TestContextLines covers every EID family: process-create (empty), network,
// image-load (+signed), process-access (target+access), file, registry, DNS.
// Ensures each non-empty field yields a labeled line and empty fields stay
// absent (so EID 1 alerts remain compact).
func TestContextLines(t *testing.T) {
	cases := []struct {
		name string
		ev   event.Event
		want []string
	}{
		{name: "process create (no context)", ev: event.Event{Image: "a.exe"}, want: nil},
		{name: "network", ev: event.Event{DstIP: "1.2.3.4", DstPort: 80, DstProto: "tcp"},
			want: []string{"dst   : 1.2.3.4:80/tcp"}},
		{name: "network no port", ev: event.Event{DstIP: "1.2.3.4"},
			want: []string{"dst   : 1.2.3.4"}},
		{name: "image load", ev: event.Event{ImageLoaded: `C:\Temp\x.dll`, Signed: "false"},
			want: []string{"loaded: C:\\Temp\\x.dll", "signed: false"}},
		{name: "process access", ev: event.Event{TargetImage: "lsass.exe", GrantedAccess: "0x1010"},
			want: []string{"target: lsass.exe", "access: 0x1010"}},
		{name: "file create", ev: event.Event{TargetFile: `C:\Temp\logins.json`},
			want: []string{"file  : C:\\Temp\\logins.json"}},
		{name: "registry", ev: event.Event{TargetRegKey: `HKCU\...\Run\X`, Details: "cmd.exe"},
			want: []string{"regkey: HKCU\\...\\Run\\X", "detail: cmd.exe"}},
		{name: "dns", ev: event.Event{QueryName: "evil.example", QueryResults: "1.2.3.4"},
			want: []string{"query : evil.example", "results: 1.2.3.4"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := contextLines(c.ev)
			if len(got) != len(c.want) {
				t.Fatalf("got %d lines %v, want %d %v", len(got), got, len(c.want), c.want)
			}
			for i, w := range c.want {
				if got[i] != w {
					t.Errorf("line %d: got %q, want %q", i, got[i], w)
				}
			}
		})
	}
}

func TestLogAlerterWritesSuppression(t *testing.T) {
	var buf bytes.Buffer
	la := NewLogAlerterTo(&buf)
	if err := la.WriteSuppression(Suppression{
		RuleID: "CRED-002", Reason: "allowlist",
		Event: event.Event{Image: "x.exe", CmdLine: "y"},
	}); err != nil {
		t.Fatalf("WriteSuppression: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SUPPRESSED") || !strings.Contains(out, "reason=allowlist") {
		t.Errorf("suppression block unexpected:\n%s", out)
	}
}

func TestDispatcherRoutesByAlertTo(t *testing.T) {
	popup := &fakeAlerter{name: "popup"}
	toast := &fakeAlerter{name: "toast"}
	logal := &fakeAlerter{name: "log"}
	d := New([]Alerter{popup, toast, logal}, 16, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)

	d.Submit(event.Hit{
		RuleID:   "X",
		Severity: event.SevCritical,
		AlertTo:  []string{"popup", "log"},
	})
	d.Submit(event.Hit{
		RuleID:   "Y",
		Severity: event.SevSuspicious,
		AlertTo:  []string{"toast", "log"},
	})

	// Give the dispatcher a moment to drain.
	waitFor(t, func() bool { return logal.Count() == 2 && popup.Count() == 1 && toast.Count() == 1 }, time.Second)

	cancel()
	if popup.Count() != 1 {
		t.Errorf("popup got %d, want 1", popup.Count())
	}
	if toast.Count() != 1 {
		t.Errorf("toast got %d, want 1", toast.Count())
	}
	if logal.Count() != 2 {
		t.Errorf("log got %d, want 2", logal.Count())
	}
	if d.Delivered() != 2 {
		t.Errorf("delivered=%d want 2", d.Delivered())
	}
}

// TestPopupQueueDoesNotBlockReader proves the key invariant: a blocking popup
// (simulated with delay) does NOT stall delivery to the other alerters. Without
// the bounded popup queue, this test deadlocks / times out.
func TestPopupQueueDoesNotBlockReader(t *testing.T) {
	popup := &fakeAlerter{name: "popup", delay: 100 * time.Millisecond}
	logal := &fakeAlerter{name: "log"}
	d := New([]Alerter{popup, logal}, 16, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	// A popup hit, then immediately a log-only hit. The log hit must land even
	// while the popup worker is blocked on its 100ms delay.
	d.Submit(event.Hit{RuleID: "P", Severity: event.SevCritical, AlertTo: []string{"popup"}})
	d.Submit(event.Hit{RuleID: "L", Severity: event.SevInfo, AlertTo: []string{"log"}})

	// log should fire well before the popup finishes.
	deadline := time.Now().Add(50 * time.Millisecond) // < popup delay
	for time.Now().Before(deadline) && logal.Count() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if logal.Count() != 1 {
		t.Fatalf("log alerter blocked by popup: logal.Count()=%d (want 1 within 50ms)", logal.Count())
	}
}

func TestDispatcherUnknownAlerterSkipped(t *testing.T) {
	logal := &fakeAlerter{name: "log"}
	d := New([]Alerter{logal}, 4, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)
	d.Submit(event.Hit{RuleID: "X", AlertTo: []string{"log", "nonexistent"}})
	waitFor(t, func() bool { return logal.Count() == 1 }, time.Second)
	cancel()
}

func TestSubmitNonBlockingOnFullBuffer(t *testing.T) {
	d := New(nil, 1, nil) // tiny buffer
	// fill the buffer
	ok := d.Submit(event.Hit{RuleID: "1"})
	if !ok {
		t.Fatal("first submit should succeed")
	}
	// buffer now full (cap 1). Second submit must not block — returns false.
	done := make(chan bool, 1)
	go func() {
		done <- d.Submit(event.Hit{RuleID: "2"})
	}()
	select {
	case res := <-done:
		if res {
			t.Error("second submit on full buffer should return false")
		}
		if d.Dropped() == 0 {
			t.Error("expected drop counter to increment")
		}
	case <-time.After(time.Second):
		t.Fatal("Submit blocked on full buffer (must be non-blocking)")
	}
}

// waitFor polls cond until it returns true or the deadline elapses.
func waitFor(t *testing.T, cond func() bool, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}
