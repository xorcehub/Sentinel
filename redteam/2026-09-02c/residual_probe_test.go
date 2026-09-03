package redteam

// Residual sweep of the round-3 fixes (2026-09-03, round 3.1): re-attacked
// the fixes themselves. R1-R4 were CONFIRMED holes (quiet = hole), fixed in
// follow-up commits and flipped to must-fire rows here. R5 is a CONFIRMED,
// OPEN residual (operator decision pending). R6-R7 pin fail-closed behavior
// of the F15 fix (extended-length/UNC spellings get no Tier-1 trust).

import (
	"testing"

	"sentinel/internal/event"
)

func TestResidualProbes(t *testing.T) {
	cases := []struct {
		id      string
		desc    string
		wantHit string // rule that MUST appear in Hits ("" = expect zero hits)
		ev      event.Event
	}{
		// R1 FIXED (config filter pinned to ^[c]:\\users\\): the fake-repo tree
		// no longer matches the filter — CONFIG-001 fires. (Was: filtered
		// silently, not even a suppressed line.)
		{"R1 (R1-fixed)", "fake-repo sentinel.exe writes the real allowlist.json — CONFIG-001 fires",
			"CONFIG-001", event.Event{EID: 11,
				Image:     `C:\evil\documents\github\leave-my-shit-alone\sentinel.exe`,
				TargetFile: `C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\config\allowlist.json`}},
		// R1-control — same write from a normal name must FIRE CONFIG-001.
		{"R1c", "control: same write from non-sentinel name",
			"CONFIG-001", event.Event{EID: 11,
				Image:     `C:\evil\documents\github\leave-my-shit-alone\probe.exe`,
				TargetFile: `C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\config\allowlist.json`}},

		// R2 FIXED (repo-dir group now mandatory, [c]:-pinned): the attacker
		// tree no longer matches — EXEC-001 fires.
		{"R2 (R2-fixed)", "bypass -File pe-triage-docker.ps1 from ATTACKER tree at drive root — EXEC-001 fires",
			"EXEC-001", event.Event{EID: 1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell.exe -ep bypass -File C:\pe_triage\scripts\pe-triage-docker.ps1`}},
		// R2-control — same shape, non-dev path must FIRE EXEC-001.
		{"R2c", "control: bypass -File same tree, non-dev name",
			"EXEC-001", event.Event{EID: 1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell.exe -ep bypass -File C:\pe_triage\scripts\totally-normal.ps1`}},

		// R3 FIXED (entries require -File + real repo path): the inert-string
		// mention no longer matches — EXEC-001 fires.
		{"R3 (R3-fixed)", "bypass -c IEX(gc ...\\sentinel\\install.ps1) mention form — EXEC-001 fires",
			"EXEC-001", event.Event{EID: 1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell.exe -ep bypass -c "IEX(gc C:\x\sentinel\install.ps1); Write-Host p"`}},

		// R4 FIXED (entry requires -File + system-drive repo path): the
		// attacker-tree invocation no longer matches — EXEC-001 fires.
		{"R4 (R4-fixed)", "bypass -File mention of gcubridge-watchdog from attacker tree — EXEC-001 fires",
			"EXEC-001", event.Event{EID: 1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell.exe -ep bypass -w h -File C:\anywhere\leave-my-shit-alone\scripts\gcubridge-watchdog.ps1`}},

		// R5 — F9 residual: the AppData install root is user-creatable; a
		// binary planted there inherits the :9080 loopback exception.
		{"R5", "binary self-planted in user-writable nhnotifsys tree on :9080",
			"", event.Event{EID: 3,
				Image: `C:\Users\ju\AppData\Local\NhNotifSys\nahimic\evil.exe`,
				DstIP: "127.0.0.1", DstPort: 9080}},

		// R6/R7 — fail-closed confirmations for F15 (extended-length prefix and
		// UNC spellings must NOT inherit Tier-1 trust).
		{"R6", "extended-length prefix Program Files beacon must fire NET-002",
			"NET-002", event.Event{EID: 3,
				Image: `\\?\C:\Program Files\Mozilla Firefox\ffupdate.exe`,
				DstIP: "203.0.113.9", DstPort: 443}},
		{"R7", "UNC admin-share Program Files beacon must fire NET-002",
			"NET-002", event.Event{EID: 3,
				Image: `\\localhost\c$\Program Files\Mozilla Firefox\ffupdate.exe`,
				DstIP: "203.0.113.9", DstPort: 443}},
	}

	for _, tc := range cases {
		eng := freshEngine(t)
		res := eng.Evaluate(&tc.ev)
		hits := hitIDs(res)
		fired := hasRule(hits, tc.wantHit)
		if tc.wantHit == "" && len(hits) != 0 {
			t.Errorf("%s (%s): expected SILENT (hole), got hits=%v supp=%v",
				tc.id, tc.desc, hits, suppIDs(res))
		} else if tc.wantHit != "" && !fired {
			t.Errorf("%s (%s): expected %s to FIRE, got hits=%v supp=%v",
				tc.id, tc.desc, tc.wantHit, hits, suppIDs(res))
		} else {
			t.Logf("%s OK (%s): hits=%v supp=%v", tc.id, tc.desc, hits, suppIDs(res))
		}
	}
}

// TestResidualLegitStaysQuiet pins that each residual fix did NOT
// over-tighten: the legitimate usage the anchor was written for still
// behaves as designed (filtered = quiet for the REAL binary).
func TestResidualLegitStaysQuiet(t *testing.T) {
	legit := []struct {
		name string
		ev   event.Event
	}{
		{
			// R3 legit: the real absolute -File install.ps1 invocation stays
			// suppressed.
			name: "R3 legit: real -File install.ps1 from the repo stays suppressed",
			ev: event.Event{EID: 1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: `powershell.exe -ExecutionPolicy Bypass -File C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\install.ps1`},
		},
		{
			// R1 legit: the REAL deployed sentinel.exe writing its own config
			// stays filtered (silent by design — CONFIG-001 is a tamper rule
			// for OTHER images, the daemon's own config writes are expected).
			name: "R1 legit: the real repo sentinel.exe writing its config stays filtered",
			ev: event.Event{EID: 11,
				Image:     `C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\sentinel.exe`,
				TargetFile: `C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\config\allowlist.json`},
		},
	}
	for _, lc := range legit {
		t.Run(lc.name, func(t *testing.T) {
			if hits := hitIDs(freshEngine(t).Evaluate(&lc.ev)); len(hits) != 0 {
				t.Errorf("legit usage must stay quiet, got hits %v", hits)
			}
		})
	}
}
