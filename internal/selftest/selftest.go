// Package selftest runs Sentinel's incident-coverage regression: it loads the
// Sigma catalog and feeds canned incident events through the engine, asserting
// each ⭐ rule fires (and benign ones don't).
//
// This is the engine-level `sentinel --self-test` (07-BUILD-PHASES.md). It does
// NOT create real artifacts (scheduled tasks, listeners, dummy vault files) —
// that live Windows-only test is a separate manual acceptance step. The engine
// self-test is the fast, portable regression gate: run after every rule/engine
// change to confirm coverage didn't degrade during tuning.
package selftest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"sentinel/internal/allowlist"
	"sentinel/internal/event"
	"sentinel/internal/rules"
	"sentinel/internal/sigmaeval"
)

// Case is one incident vector: an input Event and the set of rule IDs (x-sentinel
// mnemonics) expected to fire (or, if MustNot is set, the IDs that must NOT).
type Case struct {
	Name    string
	Event   event.Event
	Want    []string // rules that SHOULD fire
	MustNot []string // rules that must NOT fire (benign regression checks)
}

// IncidentCases returns the canned vectors derived from the real backdoor
// (docs/01-CONTEXT.md) + the coverage matrix (docs/03-RULES.md §7).
func IncidentCases() []Case {
	return []Case{
		{
			Name: "incident: conhost --headless powershell -ep bypass from ProgramData",
			Event: event.Event{
				EID:     1,
				Image:   `C:\Windows\System32\conhost.exe`,
				CmdLine: `conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\onedrive-sync.ps1"`,
			},
			Want: []string{"PERSIST-001", "EXEC-001", "EXEC-002"},
		},
		{
			Name: "incident: powershell with Reflection.Emit + WriteProcessMemory",
			Event: event.Event{
				EID:     1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell -ep bypass -c [Reflection.Emit]::... WriteProcessMemory`,
			},
			Want: []string{"EXEC-001"},
		},
		{
			Name: "incident: AMSI patch via AmsiUtils",
			Event: event.Event{
				EID:     1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell -c [Ref]::Assembly.GetType('System.Management.Automation.AmsiUtils')`,
			},
			Want: []string{"EVADE-001", "EXEC-001"},
		},
		{
			Name: "incident: lsass access by untrusted process",
			Event: event.Event{
				EID:         10,
				Image:       `C:\Users\user01\Downloads\mimikatz.exe`,
				TargetImage: `C:\Windows\System32\lsass.exe`,
			},
			Want: []string{"CRED-002"},
		},
		{
			Name: "incident: loopback driver->broker on high port",
			Event: event.Event{
				EID:     3,
				Image:   `C:\Users\user01\Downloads\driver.exe`,
				DstIP:   "127.0.0.1",
				DstPort: 58172,
			},
			Want: []string{"NET-005"},
		},
		{
			Name: "incident: WMI event subscription (fileless persistence)",
			Event: event.Event{
				EID:     20,
				Image:   `C:\Windows\System32\wbem\WmiPrvSE.exe`,
				CmdLine: `-NoProfile powershell -c evil`,
			},
			Want: []string{"PERSIST-002"},
		},
		{
			Name: "incident: browser vault file written by non-browser process",
			Event: event.Event{
				EID:        11,
				Image:      `C:\Users\user01\Downloads\stealer.exe`,
				TargetFile: `C:\Users\user01\AppData\Local\Temp\logins.json`,
			},
			Want: []string{"CRED-001"},
		},
		{
			Name: "incident: CreateRemoteThread into a foreign process",
			Event: event.Event{
				EID:         8,
				Image:       `C:\Users\user01\Downloads\injector.exe`,
				TargetImage: `C:\Program Files\Mozilla Firefox\firefox.exe`,
			},
			Want: []string{"INJECT-001"},
		},
		{
			Name: "incident: unsigned DLL loaded from Temp",
			Event: event.Event{
				EID:        7,
				Image:      `C:\Users\user01\Downloads\host.exe`,
				ImageLoaded: `C:\Users\user01\AppData\Local\Temp\payload.dll`,
				Signed:     "false",
			},
			Want: []string{"INJECT-002"},
		},
		{
			Name: "benign: powershell -c Get-Date (must NOT fire EXEC-001)",
			Event: event.Event{
				EID:     1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell -c Get-Date`,
			},
			MustNot: []string{"EXEC-001", "EXEC-002", "EVADE-001"},
		},
		{
			Name: "benign: svchost outbound to LAN (must NOT fire NET rules)",
			Event: event.Event{
				EID:     3,
				Image:   `C:\Windows\System32\svchost.exe`,
				DstIP:   "192.168.1.1",
				DstPort: 53,
			},
			MustNot: []string{"NET-002", "NET-005"},
		},
	}
}

// Result is the outcome of one case.
type Result struct {
	Case   Case
	Fired  []string // rule IDs that fired
	Passed bool
	Detail string // failure reason if !Passed
}

// Run executes all incident cases against the catalog YAML and returns per-case
// results + an overall pass bool.
//
// Uses a minimal embedded allowlist (RFC1918 + loopback CIDRs) rather than nil,
// because NET-002/003 express "public IP" as match-all + except — so the benign
// LAN case (svchost -> 192.168.x) is correctly excepted, mirroring production.
// Attack cases use untrusted paths/images so nothing is excepted for them.
func Run(catalogYAML []byte) ([]Result, bool, error) {
	compiled, err := sigmaeval.Load(catalogYAML)
	if err != nil {
		return nil, false, fmt.Errorf("load catalog: %w", err)
	}
	al, err := allowlist.Compile([]byte(selfTestAllowlist))
	if err != nil {
		return nil, false, fmt.Errorf("compile self-test allowlist: %w", err)
	}
	eng, err := rules.New(compiled, al, &nopDedup{})
	if err != nil {
		return nil, false, fmt.Errorf("build engine: %w", err)
	}

	var results []Result
	allPassed := true
	for _, c := range IncidentCases() {
		r := runCase(eng, c)
		if !r.Passed {
			allPassed = false
		}
		results = append(results, r)
	}
	return results, allPassed, nil
}

func runCase(eng *rules.Engine, c Case) Result {
	ev := c.Event
	ev.Source = event.SrcSysmonRT
	res := eng.Evaluate(&ev)
	fired := make([]string, 0, len(res.Hits))
	for _, h := range res.Hits {
		fired = append(fired, h.RuleID)
	}
	sort.Strings(fired)

	r := Result{Case: c, Fired: fired}
	firedSet := toSet(fired)

	var missing []string
	for _, w := range c.Want {
		if !firedSet[w] {
			missing = append(missing, w)
		}
	}
	var forbidden []string
	for _, m := range c.MustNot {
		if firedSet[m] {
			forbidden = append(forbidden, m)
		}
	}

	switch {
	case len(missing) > 0 && len(forbidden) > 0:
		r.Detail = fmt.Sprintf("missing %s; wrongly fired %s", strings.Join(missing, ","), strings.Join(forbidden, ","))
	case len(missing) > 0:
		r.Detail = fmt.Sprintf("did not fire: %s", strings.Join(missing, ","))
	case len(forbidden) > 0:
		r.Detail = fmt.Sprintf("should NOT have fired: %s", strings.Join(forbidden, ","))
	default:
		r.Passed = true
	}
	return r
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// nopDedup never suppresses (self-test wants every case to fire independently
// regardless of repeated target_keys across runs).
type nopDedup struct{}

func (nopDedup) SweepSeen(uint64) bool                  { return false }
func (nopDedup) MarkSeen(uint64)                        {}
func (nopDedup) ReAlert(string, string, time.Duration) bool { return true }

// selfTestAllowlist is a minimal allowlist for the regression test: RFC1918 +
// loopback CIDRs (so the benign LAN case is excepted by NET-002/003), and no
// trusted paths/hashes (so all attack cases from Downloads/Temp still fire).
// This mirrors how production is configured: private ranges excepted, untrusted
// paths flagged.
const selfTestAllowlist = `{
  "allowed_destinations": {
    "cidr": [
      "127.0.0.0/8", "::1/128",
      "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12",
      "169.254.0.0/16", "fe80::/10",
      "224.0.0.0/4", "ff00::/8"
    ]
  },
  "known_loopback_listeners": [],
  "trusted_binaries": { "sha256": [], "path": [] },
  "dev_tool_paths": { "path": [] }
}`
