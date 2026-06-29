package sigmaeval

import (
	"strings"
	"testing"

	"sentinel/internal/event"
)

// A compact slice of the catalog (see docs/03-RULES.md), as valid multi-doc YAML.
const catalogYAML = `
title: Scheduled task with bypass/headless from user-writable path
id: 2cd63037-0db9-5c16-a54d-b365c535e26a
logsource: { product: windows, service: sysmon }
detection:
  selection_launch:
    EventID: 1
    Image|endswith: ['\schtasks.exe','\powershell.exe','\pwsh.exe','\conhost.exe','\cmd.exe']
    CommandLine|contains: ['/create','-ExecutionPolicy Bypass','--headless','-Enc']
  selection_path:
    CommandLine|contains: ['ProgramData','AppData','\Temp\','\Users\Public\']
  condition: selection_launch and selection_path
level: high
x-sentinel: { id: PERSIST-001, severity: critical }
---
title: PowerShell with bypass/encoded or obfuscation/injection primitives
id: 6f4894a4-f484-5400-bc9f-ecdac0b190fe
detection:
  selection_image:
    Image|endswith: ['\powershell.exe','\pwsh.exe']
  selection_cli:
    CommandLine|contains: ['-ExecutionPolicy Bypass','-ep bypass','-enc ','FromBase64String','Reflection.Emit','GetProcAddress','WriteProcessMemory','amsi.dll','AmsiUtils']
  condition: selection_image and selection_cli
level: high
x-sentinel: { id: EXEC-001, severity: critical }
---
title: conhost --headless powershell (headless PS launch vector)
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
title: Non-Microsoft process opening lsass.exe
id: 4167ab7d-ab09-5b76-8ded-321908515ea1
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
  condition: selection
level: high
x-sentinel: { id: CRED-002, severity: critical }
---
title: Loopback connection to non-baseline listener (broker driver channel)
id: 785787a7-8a92-5364-a31c-09af26b4c43a
detection:
  selection:
    EventID: 3
    DestinationIp|re: '^(127\.|::1)'
  condition: selection
level: high
x-sentinel: { id: NET-005, severity: critical }
`

func TestLoadAndMatch(t *testing.T) {
	rules, err := Load([]byte(catalogYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}
	byXID := map[string]*Rule{}
	for _, r := range rules {
		byXID[r.XID] = r
		if r.XID == "" {
			t.Errorf("rule %q has empty x-sentinel.id", r.Title)
		}
	}

	cases := []struct {
		name string
		ev   event.Event
		want map[string]bool // x-sentinel.id -> expected to match
	}{
		{
			name: "incident conhost launch vector",
			ev: event.Event{
				EID:     1,
				Image:   `C:\Windows\System32\conhost.exe`,
				CmdLine: `conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\onedrive-sync.ps1"`,
			},
			want: map[string]bool{"PERSIST-001": true, "EXEC-002": true},
		},
		{
			name: "powershell child with -ep bypass (abbreviation fix)",
			ev: event.Event{
				EID:     1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell -ep bypass -file "C:\ProgramData\onedrive-sync.ps1"`,
			},
			want: map[string]bool{"EXEC-001": true},
		},
		{
			name: "benign powershell does not fire EXEC-001",
			ev: event.Event{
				EID:     1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell -c Get-Date`,
			},
			want: map[string]bool{},
		},
		{
			name: "lsass access matches on TargetImage (not TargetFile)",
			ev: event.Event{
				EID:         10,
				Image:       `C:\Users\user01\Downloads\probe.exe`,
				TargetImage: `C:\Windows\System32\lsass.exe`,
			},
			want: map[string]bool{"CRED-002": true},
		},
		{
			name: "loopback driver->broker connection",
			ev: event.Event{
				EID:    3,
				Image:  `C:\Users\user01\Downloads\driver.exe`,
				DstIP:  "127.0.0.1",
				DstPort: 58172,
			},
			want: map[string]bool{"NET-005": true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, r := range rules {
				if r.Match(&tc.ev) {
					got = append(got, r.XID)
				}
			}
			// every expected rule fired
			for xid := range tc.want {
				if byXID[xid] == nil {
					t.Fatalf("test wants %q but no such rule loaded", xid)
				}
				if !byXID[xid].Match(&tc.ev) {
					t.Errorf("expected %q to MATCH, it did not", xid)
				}
			}
			// no UNexpected rule fired
			wantSet := map[string]bool{}
			for k, v := range tc.want {
				wantSet[k] = v
			}
			for _, xid := range got {
				if !wantSet[xid] {
					t.Errorf("unexpected match: %q (matches: %s)", xid, strings.Join(got, ", "))
				}
			}
		})
	}
}

// TestConditionGrammar exercises the condition parser directly (and/or/not/quantifier).
func TestConditionGrammar(t *testing.T) {
	sel := map[string]func(*event.Event) bool{
		"a": func(e *event.Event) bool { return e.EID == 1 },
		"b": func(e *event.Event) bool { return e.Image == "x" },
		"selection_dns":  func(e *event.Event) bool { return e.DstPort == 53 },
		"selection_http": func(e *event.Event) bool { return e.DstPort == 80 },
	}
	cases := []struct {
		cond string
		ev   event.Event
		want bool
	}{
		{"a and b", event.Event{EID: 1, Image: "x"}, true},
		{"a and b", event.Event{EID: 1, Image: "y"}, false},
		{"a and not b", event.Event{EID: 1, Image: "y"}, true},
		{"a or b", event.Event{EID: 2, Image: "x"}, true},
		{"a or b", event.Event{EID: 2, Image: "z"}, false},
		{"1 of selection_*", event.Event{DstPort: 53}, true},
		{"1 of selection_*", event.Event{DstPort: 22}, false},
		{"all of selection_*", event.Event{DstPort: 53}, false}, // http(80) missing
	}
	for _, c := range cases {
		m, err := parseCondition(c.cond, sel)
		if err != nil {
			t.Fatalf("parse %q: %v", c.cond, err)
		}
		if got := m(&c.ev); got != c.want {
			t.Errorf("cond=%q got=%v want=%v", c.cond, got, c.want)
		}
	}
}
