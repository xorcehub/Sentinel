package rules

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinel/internal/event"
	"sentinel/internal/sigmaeval"
)

// A compact catalog exercising every engine branch: allowlist except (image +
// loopback), dedup window, severity fallback, alert routing, flood collapse.
const engineYAML = `
title: lsass access (credential dump)
id: 4167ab7d-ab09-5b76-8ded-321908515ea1
logsource: { product: windows, service: sysmon }
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
  condition: selection
level: high
x-sentinel:
  id: CRED-002
  severity: critical
  except: { image_in_allowlist: trusted_binaries }
---
title: loopback driver->broker (broker driver channel)
id: 785787a7-8a92-5364-a31c-09af26b4c43a
detection:
  selection:
    EventID: 3
    DestinationIp|re: '^(127\.|::1)'
  condition: selection
level: high
x-sentinel:
  id: NET-005
  severity: critical
  dedup: 1h
  target_key: "{{.ID}}|{{.Image}}|{{.DstIP}}:{{.DstPort}}"
  except: { dst_in_allowlist: known_loopback_listeners }
---
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
title: community rule with no x-sentinel (severity derived from level)
id: 11111111-1111-1111-1111-111111111111
detection:
  selection:
    EventID: 1
    Image|endswith: '\whoami.exe'
  condition: selection
level: low
`

// --- fakes so the engine is unit-testable without bbolt or a real allowlist ---

type fakeAL struct {
	trustedSHA  map[string]bool
	trustedPath []*regexp.Regexp
	devPath     []*regexp.Regexp
	cidrs       []*net.IPNet
	loopback    map[string]bool
}

func (a *fakeAL) ImageTrusted(e *event.Event) bool {
	if e.Hashes != nil {
		if a.trustedSHA[strings.ToLower(e.Hashes["SHA256"])] {
			return true
		}
	}
	np := strings.ToLower(e.Image)
	for _, re := range a.trustedPath {
		if re.MatchString(np) {
			return true
		}
	}
	return false
}
func (a *fakeAL) ImageInDevTools(p string) bool {
	np := strings.ToLower(p)
	for _, re := range a.devPath {
		if re.MatchString(np) {
			return true
		}
	}
	return false
}
func (a *fakeAL) DstInCIDR(ip string) bool {
	pi := net.ParseIP(ip)
	for _, n := range a.cidrs {
		if n.Contains(pi) {
			return true
		}
	}
	return false
}
func (a *fakeAL) DstIsKnownLoopback(ip string, port int) bool {
	return a.loopback[strings.ToLower(ip)+":"+strconv.Itoa(port)]
}

type memDedup struct {
	mu   sync.Mutex
	max  uint64
	last map[string]time.Time
}

func newMemDedup() *memDedup { return &memDedup{last: map[string]time.Time{}} }
func (m *memDedup) SweepSeen(id uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return id > 0 && id <= m.max
}
func (m *memDedup) MarkSeen(id uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id > m.max {
		m.max = id
	}
}
func (m *memDedup) ReAlert(ruleID, tk string, win time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := ruleID + "|" + tk
	now := time.Now()
	if t, ok := m.last[k]; ok && now.Sub(t) < win {
		return false
	}
	m.last[k] = now
	return true
}

// --- helpers ---

func newEngine(t *testing.T, al Allowlist) *Engine {
	t.Helper()
	rules, err := sigmaeval.Load([]byte(engineYAML))
	if err != nil {
		t.Fatalf("sigmaeval Load: %v", err)
	}
	eng, err := New(rules, al, newMemDedup())
	if err != nil {
		t.Fatalf("engine New: %v", err)
	}
	return eng
}

func hitIDs(res *Evaluation) []string {
	var ids []string
	for _, h := range res.Hits {
		ids = append(ids, h.RuleID)
	}
	return ids
}
func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// --- tests ---

func TestIncidentHitsAndRouting(t *testing.T) {
	eng := newEngine(t, &fakeAL{trustedSHA: map[string]bool{}, loopback: map[string]bool{}})
	// conhost headless incident -> EXEC-002, critical, popup routed
	res := eng.Evaluate(&event.Event{
		EID:     1,
		Image:   `C:\Windows\System32\conhost.exe`,
		CmdLine: `conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\x.ps1"`,
	})
	if !contains(hitIDs(res), "EXEC-002") {
		t.Fatalf("EXEC-002 should fire; got %v", hitIDs(res))
	}
	for _, h := range res.Hits {
		if h.RuleID == "EXEC-002" {
			if h.Severity != event.SevCritical {
				t.Errorf("EXEC-002 severity=%s want critical", h.Severity)
			}
			if !contains(h.AlertTo, "popup") {
				t.Errorf("critical should route popup; got %v", h.AlertTo)
			}
		}
	}
}

func TestAllowlistSuppressesByHash(t *testing.T) {
	// Defender (trusted SHA) opens lsass -> CRED-002 matches but is suppressed.
	al := &fakeAL{trustedSHA: map[string]bool{"defenderhash": true}}
	eng := newEngine(t, al)
	res := eng.Evaluate(&event.Event{
		EID:         10,
		Image:       `C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe`,
		TargetImage: `C:\Windows\System32\lsass.exe`,
		Hashes:      map[string]string{"SHA256": "DefenderHash"},
	})
	if contains(hitIDs(res), "CRED-002") {
		t.Fatalf("CRED-002 should be suppressed by trusted hash; got hits %v", hitIDs(res))
	}
	var got bool
	for _, s := range res.Suppressed {
		if s.RuleID == "CRED-002" && s.Reason == "allowlist" {
			got = true
		}
	}
	if !got {
		t.Fatalf("expected CRED-002 allowlist suppression; got %+v", res.Suppressed)
	}

	// Same rule, untrusted process -> fires.
	res2 := eng.Evaluate(&event.Event{
		EID:         10,
		Image:       `C:\Users\user01\Downloads\probe.exe`,
		TargetImage: `C:\Windows\System32\lsass.exe`,
	})
	if !contains(hitIDs(res2), "CRED-002") {
		t.Fatalf("untrusted lsass access should fire CRED-002; got %v", hitIDs(res2))
	}
}

func TestLoopbackAllowlistSetTypeDriven(t *testing.T) {
	// NET-005 except references known_loopback_listeners (host:port set).
	al := &fakeAL{loopback: map[string]bool{"127.0.0.1:9080": true}, trustedSHA: map[string]bool{}}
	eng := newEngine(t, al)

	// traffic to a known dev port -> suppressed
	res := eng.Evaluate(&event.Event{EID: 3, Image: `C:\app.exe`, DstIP: "127.0.0.1", DstPort: 9080})
	if contains(hitIDs(res), "NET-005") {
		t.Fatalf("known loopback should be suppressed; got %v", hitIDs(res))
	}

	// traffic to the broker port (NOT known) -> fires, critical, popup
	res2 := eng.Evaluate(&event.Event{EID: 3, Image: `C:\Users\user01\Downloads\driver.exe`, DstIP: "127.0.0.1", DstPort: 58172})
	if !contains(hitIDs(res2), "NET-005") {
		t.Fatalf("broker loopback should fire NET-005; got %v", hitIDs(res2))
	}
}

func TestDedupWindow(t *testing.T) {
	eng := newEngine(t, &fakeAL{trustedSHA: map[string]bool{}, loopback: map[string]bool{}})
	mk := func() *event.Event {
		return &event.Event{EID: 3, Image: `C:\driver.exe`, DstIP: "127.0.0.1", DstPort: 58172}
	}
	r1 := eng.Evaluate(mk())
	if !contains(hitIDs(r1), "NET-005") {
		t.Fatal("first should fire")
	}
	// identical target within 1h window -> suppressed as dedup-window
	r2 := eng.Evaluate(mk())
	if contains(hitIDs(r2), "NET-005") {
		t.Fatal("second identical should be deduped")
	}
	var dd bool
	for _, s := range r2.Suppressed {
		if s.RuleID == "NET-005" && s.Reason == "dedup-window" {
			dd = true
		}
	}
	if !dd {
		t.Fatalf("expected dedup-window suppression; got %+v", r2.Suppressed)
	}
	// different target -> fires again (target_key includes DstPort)
	r3 := eng.Evaluate(&event.Event{EID: 3, Image: `C:\driver.exe`, DstIP: "127.0.0.1", DstPort: 58173})
	if !contains(hitIDs(r3), "NET-005") {
		t.Fatal("different target_key should fire")
	}
}

func TestRTSweepRecordIDGate(t *testing.T) {
	eng := newEngine(t, &fakeAL{trustedSHA: map[string]bool{}, loopback: map[string]bool{}})
	// RT observes event with RecordID 100
	rt := eng.Evaluate(&event.Event{
		Source: event.SrcSysmonRT, RecordID: 100, EID: 1,
		Image: `C:\Windows\System32\conhost.exe`,
		CmdLine: `conhost.exe --headless powershell`,
	})
	if !contains(hitIDs(rt), "EXEC-002") {
		t.Fatal("RT event should fire EXEC-002")
	}
	// Sweep replays the same RecordID -> gated out entirely (no hits, no suppressions)
	sw := eng.Evaluate(&event.Event{
		Source: event.SrcSysmonSweep, RecordID: 100, EID: 1,
		Image: `C:\Windows\System32\conhost.exe`,
		CmdLine: `conhost.exe --headless powershell`,
	})
	if len(sw.Hits) != 0 || len(sw.Suppressed) != 0 {
		t.Fatalf("sweep replay of seen RecordID must be fully skipped; got hits=%v supp=%d", hitIDs(sw), len(sw.Suppressed))
	}
}

func TestCommunityRuleSeverityFallback(t *testing.T) {
	eng := newEngine(t, &fakeAL{trustedSHA: map[string]bool{}, loopback: map[string]bool{}})
	// whoami rule has no x-sentinel.severity; level: low -> info -> alerters [log]
	res := eng.Evaluate(&event.Event{EID: 1, Image: `C:\Windows\System32\whoami.exe`})
	var found bool
	for _, h := range res.Hits {
		if h.RuleName != "" && h.Severity == event.SevInfo {
			found = true
			if len(h.AlertTo) != 1 || h.AlertTo[0] != "log" {
				t.Errorf("info should route [log] only; got %v", h.AlertTo)
			}
		}
	}
	if !found {
		t.Fatalf("community whoami rule should fire as info; got %+v", res.Hits)
	}
}

func TestTargetKeyTemplateRendersFields(t *testing.T) {
	// NET-005 target_key uses {{.Image}}|{{.DstIP}}:{{.DstPort}} via the embedded
	// *event.Event. Confirm dedup keys on the rendered string by observing that
	// changing DstPort produces a different dedup outcome (already covered by
	// TestDedupWindow). Here we directly exercise targetKey().
	//
	// Contract: targetKey() receives an ALREADY-NORMALIZED event (pathnorm is
	// Evaluate's job — it runs once at the top of Evaluate before any rule
	// processing). So feed this direct caller lowercased input, exactly as
	// production does; testing targetKey's own template rendering, not normalization.
	eng := newEngine(t, &fakeAL{trustedSHA: map[string]bool{}, loopback: map[string]bool{}})
	rules, _ := sigmaeval.Load([]byte(engineYAML))
	var net005 *sigmaeval.Rule
	for _, r := range rules {
		if r.XID == "NET-005" {
			net005 = r
		}
	}
	e := &event.Event{Image: `c:\x.exe`, DstIP: "127.0.0.1", DstPort: 58172}
	tk := eng.targetKey("NET-005", net005, e)
	want := "NET-005|c:\\x.exe|127.0.0.1:58172"
	if tk != want {
		t.Errorf("targetKey = %q, want %q", tk, want)
	}
}
