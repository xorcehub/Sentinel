package alert

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"git.sr.ht/~jackmordaunt/go-toast"

	"sentinel/internal/event"
)

// fakeAlerter records every Alert call. Safe for concurrent use.
type fakeAlerter struct {
	name  string
	mu    sync.Mutex
	calls []event.Hit
	delay time.Duration // optional, to simulate a slow alerter (popup)
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
// TestLogAlerterShowsParent is the regression for the PERSIST-001/EXEC-001
// gap: a hit spawned by a dev tool (cursor.exe -> powershell.exe -> Temp\ps.ps1)
// looked like malware in ALERTS.log/EventLog because only the popup surfaced the
// parent. Now contextLines emits parent/pcmd, so all channels agree and the
// lineage is visible without opening the popup.
func TestLogAlerterShowsParent(t *testing.T) {
	var buf bytes.Buffer
	la := NewLogAlerterTo(&buf)
	h := event.Hit{
		RuleID: "PERSIST-001", RuleName: "Scheduled task with bypass/headless from user-writable path",
		Severity: event.SevCritical,
		Event: event.Event{
			EID:           1,
			Image:         `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine:       `powershell.exe -ExecutionPolicy Bypass -File C:\Users\j\AppData\Local\Temp\ps-script-xyz.ps1`,
			ParentImage:   `C:\Users\j\AppData\Local\Programs\cursor\Cursor.exe`,
			ParentCmdLine: `C:\Users\j\AppData\Local\Programs\cursor\Cursor.exe`,
		},
		Matched: "PERSIST-001 on powershell.exe",
		AlertTo: []string{"popup", "toast", "log", "eventlog"},
		Time:    time.Date(2026, 7, 1, 17, 36, 31, 0, time.UTC),
	}
	if err := la.Alert(h); err != nil {
		t.Fatalf("Alert: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"rule=PERSIST-001", "parent:", "\\cursor\\Cursor.exe", "pcmd  :"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestLogAlerterShowsNetworkContext(t *testing.T) {
	var buf bytes.Buffer
	la := NewLogAlerterTo(&buf)
	h := event.Hit{
		RuleID: "NET-002", RuleName: "Outbound to public host",
		Severity: event.SevSuspicious,
		Event: event.Event{
			EID:      3,
			Image:    `C:\dev\pi-lite.exe`,
			DstIP:    "142.93.4.11",
			DstPort:  443,
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

// TestLogAlerterShowsHidAndRec is the correlation guarantee: the ALERTS.log
// block must carry the hit's hid so it joins 1:1 with the msg=HIT line in
// sentinel.log, plus rec (source Sysmon EventRecordID) for pivoting to Event
// Viewer. rec is OMITTED for baseline pseudo-events (RecordID=0).
func TestLogAlerterShowsHidAndRec(t *testing.T) {
	var buf bytes.Buffer
	la := NewLogAlerterTo(&buf)
	const hid = "R-20260701-K7Q3F-000042"
	h := event.Hit{
		ID:       hid,
		RuleID:   "PERSIST-001",
		RuleName: "Scheduled task with bypass",
		Severity: event.SevCritical,
		Event: event.Event{
			RecordID: 280954,
			Image:    `C:\Windows\System32\powershell.exe`,
			CmdLine:  `powershell.exe -ExecutionPolicy Bypass -File C:\Users\j\Temp\x.ps1`,
		},
		Matched: "PERSIST-001 on powershell.exe",
		AlertTo: []string{"popup", "log", "eventlog"},
		Time:    time.Date(2026, 7, 1, 17, 36, 31, 0, time.UTC),
	}
	if err := la.Alert(h); err != nil {
		t.Fatalf("Alert: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"hid=" + hid, "rec=280954", "rule=PERSIST-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}

	// Baseline pseudo-event (RecordID=0): rec must NOT appear (0 is meaningless).
	var buf2 bytes.Buffer
	la2 := NewLogAlerterTo(&buf2)
	if err := la2.Alert(event.Hit{
		ID: hid, RuleID: "BASE-001", Severity: event.SevSuspicious,
		Event:   event.Event{Image: `C:\x.exe`}, // RecordID zero-value
		Matched: "BASE-001", Time: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Alert baseline: %v", err)
	}
	if out2 := buf2.String(); strings.Contains(out2, "rec=") {
		t.Errorf("baseline hit (RecordID=0) must omit rec, got:\n%s", out2)
	}
}

// TestLogAlerterSanitizesNewline is the F1 regression: an attacker controls
// several event fields verbatim (command line, registry value data, DNS
// answer, ...), so a '\n' in any of them must NOT inject a forged line into
// ALERTS.log (unprivileged append-forgery). sanitize() maps C0 controls to a
// space; the forged content is flattened onto its context line as inert data
// instead of starting a new "[ts] CRITICAL ..." block. The literal attack
// tokens may still appear as text — what matters is they can no longer begin a
// line that mimics an alert block header. Covers the CmdLine/ParentCmdLine,
// registry Details (the confirmed vector: the Run-key value writer controls
// those bytes), and DNS QueryName/QueryResults paths through contextLines.
func TestLogAlerterSanitizesNewline(t *testing.T) {
	var buf bytes.Buffer
	la := NewLogAlerterTo(&buf)
	h := event.Hit{
		RuleID: "EXEC-001", RuleName: "PS bypass",
		Severity: event.SevCritical,
		Event: event.Event{
			Image:         `C:\Windows\System32\powershell.exe`,
			CmdLine:       "powershell -c evil\n[2099-01-01T00:00:00+00:00] CRITICAL hid=FAKE rule=PWNED",
			ParentImage:   `C:\parent.exe`,
			ParentCmdLine: "parent\r\ninject",
			// Registry value data (Details) is a confirmed forgery vector: the
			// attacker writing the Run-key value (the act PERSIST rules detect)
			// controls these bytes, and a REG_SZ value holds 0x0A. TargetRegKey
			// gates Details into contextLines.
			TargetRegKey: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Evil`,
			Details:      "evil.exe\n[2099-01-01T00:00:00+00:00] CRITICAL hid=DETAILFORGE rule=PWN-REG",
			// DNS answer strings are also attacker-controlled (rogue resolver).
			QueryName:    "evil.example\n[2099] CRITICAL hid=DNSFORGE",
			QueryResults: "1.2.3.4\nFORGED-RESULTS",
		},
		Matched: "EXEC-001\ton powershell",
		AlertTo: []string{"log"},
		Time:    time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := la.Alert(h); err != nil {
		t.Fatalf("Alert: %v", err)
	}
	out := buf.String()
	// No line may look like a forged alert header. The real block has exactly
	// one header line (starts with '['); a successful injection would add a
	// second. Lines beginning with '[' = header candidates.
	headers := 0
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "[") {
			headers++
		}
	}
	if headers != 1 {
		t.Errorf("want exactly 1 header line, got %d (forged header injected?):\n%s", headers, out)
	}
	// Structural check: the sanitized block has the same newline count as a
	// clean hit whose cmd/pcmd carry the same text without control chars. A
	// forged block would add lines.
	var clean bytes.Buffer
	NewLogAlerterTo(&clean).Alert(event.Hit{
		RuleID: "EXEC-001", RuleName: "PS bypass", Severity: event.SevCritical,
		Event: event.Event{
			Image:         `C:\Windows\System32\powershell.exe`,
			CmdLine:       "powershell -c evil [2099-01-01T00:00:00+00:00] CRITICAL hid=FAKE rule=PWNED",
			ParentImage:   `C:\parent.exe`,
			ParentCmdLine: "parent inject",
			TargetRegKey:  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Evil`,
			Details:       "evil.exe [2099-01-01T00:00:00+00:00] CRITICAL hid=DETAILFORGE rule=PWN-REG",
			QueryName:     "evil.example [2099] CRITICAL hid=DNSFORGE",
			QueryResults:  "1.2.3.4 FORGED-RESULTS",
		},
		Matched: "EXEC-001 on powershell", AlertTo: []string{"log"},
		Time: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	})
	if nlCount(out) != nlCount(clean.String()) {
		t.Errorf("newline count differs: attack=%d clean=%d\n--- attack ---\n%s", nlCount(out), nlCount(clean.String()), out)
	}
}

func nlCount(s string) int { return strings.Count(s, "\n") }

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"clean", "clean"},
		{"line1\nline2", "line1 line2"},
		{"a\rb\tc\fd", "a b c d"},
		{"null\x00byte", "null byte"},
		{"\x1funit\x1f", " unit "},
		{"keep émojiié ✓", "keep émojiié ✓"}, // non-ASCII passes through untouched
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestContextLines(t *testing.T) {
	cases := []struct {
		name string
		ev   event.Event
		want []string
	}{
		{name: "process create (no context)", ev: event.Event{Image: "a.exe"}, want: nil},
		{name: "process create + parent lineage", ev: event.Event{Image: `C:\Windows\System32\powershell.exe`, ParentImage: `C:\cursor.exe`, ParentCmdLine: `cursor.exe --run-extension`},
			want: []string{"parent: C:\\cursor.exe", "pcmd  : cursor.exe --run-extension"}},
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

// TestDispatcherSkipsPopupWhenNotRegistered pins the -popup=false contract:
// when no popup alerter is registered, a critical hit whose AlertTo still
// requests "popup" (engine declares intent; dispatcher delivers what's wired)
// must (a) still hit its other alerters and (b) NOT touch the popup queue —
// so a burst can't spuriously increment Dropped and surface as a fake health
// problem in the heartbeat.
func TestDispatcherSkipsPopupWhenNotRegistered(t *testing.T) {
	logal := &fakeAlerter{name: "log"}
	// popup deliberately NOT registered (operator ran -popup=false)
	d := New([]Alerter{logal}, 16, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)

	d.Submit(event.Hit{RuleID: "C", Severity: event.SevCritical, AlertTo: []string{"popup", "log"}})
	waitFor(t, func() bool { return logal.Count() == 1 }, time.Second)
	cancel()

	if logal.Count() != 1 {
		t.Errorf("log should fire once; got %d", logal.Count())
	}
	if d.Dropped() != 0 {
		t.Errorf("popup-not-wired must not count as dropped; got %d (popup queue touched?)", d.Dropped())
	}
}

// TestCriticalNotificationIsLoud pins the "what makes a critical toast stand
// out" policy: looping alarm audio, long duration, looped, 🛑-prefixed title,
// grouped under the Sentinel AppID. Pure (no Push) so it asserts the config
// without firing a WinRT toast. If someone weakens the alarm by accident this
// fails. Tune the policy in criticalNotification and update the expectations
// here in the same change.
func TestCriticalNotificationIsLoud(t *testing.T) {
	n := criticalNotification("Sentinel: EXEC-001", "CRITICAL — powershell.exe — -ep bypass x.ps1")
	if n.Audio != toast.LoopingAlarm {
		t.Errorf("critical toast Audio = %q, want LoopingAlarm (must stand out from silent suspicious tier)", n.Audio)
	}
	if n.Duration != toast.Long {
		t.Errorf("critical toast Duration = %q, want Long", n.Duration)
	}
	if !n.Loop {
		t.Error("critical toast Loop = false, want true (alarm must repeat until dismissed)")
	}
	if !strings.HasPrefix(n.Title, "🛑") {
		t.Errorf("critical toast Title = %q, want 🛑 prefix", n.Title)
	}
	if n.AppID != toastAppID {
		t.Errorf("critical toast AppID = %q, want %q (group with suspicious-tier toasts)", n.AppID, toastAppID)
	}
}

// TestToastTextCriticalEnriched pins that the former-popup tier carries the
// command line in the toast body (the MessageBox showed it) so a loud critical
// toast is actionable. Suspicious stays compact (image only).
func TestToastTextCriticalEnriched(t *testing.T) {
	title, body := toastText(event.Hit{
		Severity: event.SevCritical,
		RuleName: "PS bypass",
		Event:    event.Event{Image: `C:/bad.exe`, CmdLine: `-enc SGVsbG8=`},
	})
	if !strings.Contains(body, `-enc SGVsbG8=`) {
		t.Errorf("critical toast body should include the command line; got %q", body)
	}
	if !strings.HasPrefix(title, "Sentinel: ") {
		t.Errorf("title prefix; got %q", title)
	}
	// Suspicious tier: no command line in the body.
	_, sbody := toastText(event.Hit{
		Severity: event.SevSuspicious,
		RuleName: "NET",
		Event:    event.Event{Image: `C:/net.exe`, CmdLine: `should-not-appear`},
	})
	if strings.Contains(sbody, `should-not-appear`) {
		t.Errorf("suspicious toast body should NOT include cmd; got %q", sbody)
	}
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
