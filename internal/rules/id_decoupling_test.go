package rules

import (
	"regexp"
	"strings"
	"testing"

	"sentinel/internal/event"
	"sentinel/internal/sigmaeval"
)

// idRe is the documented correlation-ID format (see id.go, 05-ALERTING.md §5).
var decouplingIDRe = regexp.MustCompile(`^R-\d{8}-[0-9A-Z]{5}-\d{6}$`)

// TestBuildHitStampsID pins that every Hit produced by Evaluate carries a
// well-formed, non-empty correlation ID. Hits are stamped in exactly one place
// (buildHit), so this one check covers every rule type.
func TestBuildHitStampsID(t *testing.T) {
	eng := newEngine(t, &fakeAL{trustedSHA: map[string]bool{}, loopback: map[string]bool{}})
	res := eng.Evaluate(&event.Event{
		EID:     1,
		Image:   `C:\Windows\System32\conhost.exe`,
		CmdLine: `conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\x.ps1"`,
	})
	if len(res.Hits) == 0 {
		t.Fatal("expected at least one hit")
	}
	h := res.Hits[0]
	if h.ID == "" {
		t.Fatal("Hit.ID must be stamped by buildHit, got empty")
	}
	if !decouplingIDRe.MatchString(h.ID) {
		t.Errorf("Hit.ID %q does not match R-YYYYMMDD-<nonce>-<NNNNNN>", h.ID)
	}
}

// twoRuleYAML defines two rules that BOTH match the same event — a powershell
// bypass launch from a user-writable path. This is the real-world PERSIST-001 +
// EXEC-001 overlap (both fire on `powershell -ep bypass -File C:\Users\..\Temp\..ps1`).
const twoRuleYAML = `
title: bypass powershell launch
id: aaaaaaaa-0000-0000-0000-000000000001
logsource: { product: windows, service: sysmon }
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-ExecutionPolicy Bypass'
  condition: selection
level: high
x-sentinel: { id: EXEC-001, severity: critical }
---
title: bypass from user-writable path
id: aaaaaaaa-0000-0000-0000-000000000002
logsource: { product: windows, service: sysmon }
detection:
  selection:
    EventID: 1
    CommandLine|contains: ['ExecutionPolicy Bypass', 'Temp']
  condition: selection
level: high
x-sentinel: { id: PERSIST-001, severity: critical }
`

// TestOneEventMultipleRulesDistinctIDs is the core decoupling guarantee: a
// single Sysmon event firing two rules must produce two Hits with DISTINCT
// correlation IDs. The source RecordID is identical across both hits, so rec
// alone could not tell them apart — this is exactly why the synthetic hid exists
// rather than reusing RecordID. (This is the EXEC-001 + PERSIST-001 overlap
// observed in the operator's real ALERTS.log, both at the same timestamp.)
func TestOneEventMultipleRulesDistinctIDs(t *testing.T) {
	rs, err := sigmaeval.Load([]byte(twoRuleYAML))
	if err != nil {
		t.Fatalf("sigmaeval Load: %v", err)
	}
	eng, err := New(rs, &fakeAL{trustedSHA: map[string]bool{}, loopback: map[string]bool{}}, newMemDedup())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := &event.Event{
		EID:      1,
		RecordID: 4242, // identical across both hits — rec would collide, hid must not
		Image:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine:  `powershell.exe -ExecutionPolicy Bypass -File C:\Users\jurij\AppData\Local\Temp\evil.ps1`,
	}
	res := eng.Evaluate(ev)
	if len(res.Hits) != 2 {
		t.Fatalf("need exactly 2 hits to test distinct IDs, got %d", len(res.Hits))
	}
	seen := map[string]bool{}
	for _, h := range res.Hits {
		if seen[h.ID] {
			t.Fatalf("two hits share ID %q — multiple rules on one event must get distinct IDs", h.ID)
		}
		seen[h.ID] = true
		if !decouplingIDRe.MatchString(h.ID) {
			t.Errorf("Hit.ID %q malformed", h.ID)
		}
		if h.Event.RecordID != 4242 {
			t.Errorf("rec must be preserved: want 4242, got %d", h.Event.RecordID)
		}
	}
}

// TestSuppressionStampedWithID confirms dedup-window suppressions also carry an
// hid, so a rate-limit decision in sentinel.log cross-refs its event (the whole
// point of correlating suppressed lines too).
func TestSuppressionStampedWithID(t *testing.T) {
	eng := newEngine(t, &fakeAL{trustedSHA: map[string]bool{}, loopback: map[string]bool{}})
	// NET-005 with a non-allowlisted loopback target fires once, then a second
	// identical event within the 1h dedup window is suppressed as dedup-window.
	ev := &event.Event{EID: 3, RecordID: 7, Image: `C:\bad.exe`, DstIP: "127.0.0.1", DstPort: 9999}
	eng.Evaluate(ev) // first -> HIT
	res2 := eng.Evaluate(ev)
	if len(res2.Suppressed) == 0 {
		t.Fatal("expected a dedup-window suppression on the second identical event")
	}
	s := res2.Suppressed[0]
	if s.ID == "" || !strings.HasPrefix(s.ID, "R-") {
		t.Errorf("suppression must carry a stamped hid, got %q", s.ID)
	}
}
