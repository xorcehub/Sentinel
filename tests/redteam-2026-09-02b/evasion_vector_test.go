// Package redteam — round-2 evasion vectors against the REAL catalog
// (rules.d/*.yml) + REAL allowlist (config/allowlist.json) + the REAL engine.
//
// Round 1 (docs/redteam-plan-2026-09-02.md) found the suffix-trust hole in
// filter_cursor_agent; it is fixed. This round probes NEW holes, found by
// reading the rules/allowlist semantics (sigmaeval: contains/endswith
// case-insensitive; re always (?i) unanchored unless anchored; selections AND
// across fields / OR across values; absent field => no match; engine excepts
// are ORed).
//
// Every "bypass" row asserts the SILENCE the current rules produce. Every
// bypass has a control row (same event, one deviation) that must FIRE — so a
// quiet result is attributable to the hole, not to lost telemetry. Controls
// are in TestBypassControls.
//
// Operator constraint honored: this test runs IN-PROCESS only. It writes
// nothing outside this directory, touches no registry/Temp/tasks — the
// "attacks" are event shapes fed straight to the engine the daemon runs.
//
// When a fix lands for a finding, its quiet row starts failing: move the row
// to the controls table (must-fire), like round 1 did.
package redteam

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"sentinel/internal/allowlist"
	"sentinel/internal/event"
	"sentinel/internal/rules"
	"sentinel/internal/sigmaeval"
)

// ---- harness (mirrors internal/rules/catalog_blindspot_test.go) ----

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = .../tests/redteam-2026-09-02b/evasion_vector_test.go -> root 2 up
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func loadRealCatalog(t *testing.T) []*sigmaeval.Rule {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "rules.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("rules.d not present (%v)", err)
	}
	var concat []byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext != ".yml" && ext != ".yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		concat = append(concat, b...)
		if len(b) > 0 && b[len(b)-1] != '\n' {
			concat = append(concat, '\n')
		}
		concat = append(concat, "---\n"...)
	}
	rs, err := sigmaeval.Load(concat)
	if err != nil {
		t.Fatalf("load real catalog: %v", err)
	}
	return rs
}

func loadRealAllowlist(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	al, err := allowlist.Load(filepath.Join(repoRoot(t), "config", "allowlist.json"))
	if err != nil {
		t.Skipf("allowlist.json not present (%v)", err)
	}
	return al
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

// freshEngine: real catalog + real allowlist + fresh dedup per row.
func freshEngine(t *testing.T) *rules.Engine {
	t.Helper()
	eng, err := rules.New(loadRealCatalog(t), loadRealAllowlist(t), newMemDedup())
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	return eng
}

func hitIDs(res *rules.Evaluation) []string {
	out := make([]string, 0, len(res.Hits))
	for _, h := range res.Hits {
		out = append(out, h.RuleID)
	}
	return out
}

func hasRule(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// ---- the bypass table ----

type bypassCase struct {
	finding string // F-id in README.md
	name    string
	ev      event.Event
	// wantZeroHits: NO rule in the catalog produces a hit for this event.
	wantZeroHits bool
	// wantQuietRule: this specific rule must NOT fire (other rules may).
	wantQuietRule string
}

var bypassCases = []bypassCase{
	// F1 FIXED (2026-09-02b, exec.yml): abbreviated PS flags now fire EXEC-001.
	// Rows moved to TestBypassControls (F1-fixed:*). Residual, documented: the
	// token list is still whack-a-mole against PS prefix matching — the durable
	// fix is a PS-args-parsing engine helper.

	// F2 FIXED (2026-09-02b, allowlist.json): pe-triage-docker entry is now
	// path-anchored on the pe_triage repo's scripts dir. Row moved to
	// TestBypassControls (F2-fixed). See also internal/allowlist
	// TestCmdLineInDevScripts / TestProductionAllowlistDevTuning.

	// F3 PARTIALLY FIXED (2026-09-02b, persistence.yml): %temp%/%appdata%
	// env-var tokens added to selection_path — the env-var row moved to
	// TestBypassControls (F3a-fixed). REMAINING bypass: /xml keeps the action
	// out of the cmdline entirely; needs an engine helper resolving the XML.
	// Backstop: BASE-001 daily autoruns diff (task appears, <=24h delay).
	{
		finding: "F3",
		name:    "schtasks /create /xml (task definition carries the action, not the cmdline)",
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\schtasks.exe`,
			CmdLine: `schtasks.exe /create /tn OneDriveUpd /xml C:\Users\ju\Documents\upd-task.xml /f`},
		wantZeroHits:  true,
		wantQuietRule: "PERSIST-001",
	},

	// F4 FIXED (2026-09-02b, persistence.yml): \Windows\Load + StubPath
	// tokens added to PERSIST-003. Both rows moved to TestBypassControls
	// (F4-fixed). Anchored on \Windows\Load rather than the whole
	// CurrentVersion\Windows key to keep per-user Device/printer churn quiet.
	// REFUTED (kept as control CU1): \\Environment\\UserInitMprLogonScript
	// FIRES — PERSIST-003's unanchored '\\Userinit' token substring-matches any
	// value NAMED Userinit*. Honest log: this hypothesis was wrong.

	// F5 FIXED (2026-09-02b, persistence.yml): extension list extended with
	// jse|vbe|wsf|hta|scr. Rows moved to TestBypassControls (F5-fixed).

	// F6 REFUTED: sigmaeval treats a value LIST under one field as OR, not AND,
	// so 'Classes\\CLSID' alone satisfies PERSIST-006's selection — LocalServer32
	// and TreatAs hijacks from the USER hive fire (kept as control CU2). The
	// remaining quiet shape (machine-hive CLSID write, admin-owned payload)
	// needs an admin writer = out of scope per THREAT-MODEL.

	// F7 FIXED (2026-09-02b, inject.yml): Desktop|Documents added to
	// INJECT-002's ImageLoaded list. Both rows moved to TestBypassControls
	// (F7-fixed; the repo-tree row closes via Documents). Residual: any OTHER
	// user-writable dir — durable fix = user-writable-path helper.

	// F8a FIXED (2026-09-02b, net.yml): Users\Public added to NET-004's image
	// list. Both rows moved to TestBypassControls (F8a-fixed). DoH CIDRs kept
	// (system resolver); residual = other user-writable dirs outside the list.

	// F8b — fully silent LOOPBACK C2: known_loopback_listeners excepts
	// 127.0.0.1:9080 from NET-005; loopback dst is also inside
	// allowed_destinations for NET-002/003. Image deliberately in Downloads
	// (NOT one of NET-004's Temp/AppData/ProgramData/Users\Public dirs) so this
	// row isolates the NET-005 except — after the F8a fix, a Users\Public image
	// would fire NET-004 for a different reason.
	{
		finding: "F8b",
		name:    "loopback C2 on the allowlisted port: 127.0.0.1:9080 from a Downloads image — zero hits",
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\payload.exe`,
			DstIP: "127.0.0.1", DstPort: 9080},
		wantZeroHits:  true,
		wantQuietRule: "*",
	},

	// Documented-accepted residual (confirmed, not new): dev_tool_paths grants
	// NET-002/003/004 quiet to anything self-named under %USERPROFILE%\go\bin
	// (Bypass-B, accepted in allowlist.json comments). Pinned so the accepted
	// risk stays visible as a red row if the posture ever changes.
	{
		finding: "F0-accepted",
		name:    "self-named dev tool: %USERPROFILE%\\go\\bin\\evil.exe beacons publicly — zero hits (documented accepted)",
		ev: event.Event{EID: 3, Image: `C:\Users\ju\go\bin\evil.exe`,
			DstIP: "203.0.113.9", DstPort: 443},
		wantZeroHits:  true,
		wantQuietRule: "*",
	},
}

// TestBypassVectorsAreQuiet pins the CURRENT silence of every bypass row.
// A failure here means a fix landed — flip the row into TestBypassControls.
func TestBypassVectorsAreQuiet(t *testing.T) {
	for _, bc := range bypassCases {
		t.Run(bc.finding+"/"+bc.name, func(t *testing.T) {
			res := freshEngine(t).Evaluate(&bc.ev)
			ids := hitIDs(res)
			if bc.wantZeroHits && len(res.Hits) != 0 {
				t.Errorf("expected ZERO hits (hole closed?), got %v\nsuppressed: %v", ids, suppIDs(res))
			}
			if bc.wantQuietRule != "*" && hasRule(ids, bc.wantQuietRule) {
				t.Errorf("expected %s QUIET, it fired\nall hits: %v", bc.wantQuietRule, ids)
			}
		})
	}
}

// ---- controls: same shape minus the hole, MUST fire ----

type controlCase struct {
	name string
	rule string
	sev  event.Severity
	ev   event.Event
}

var controlCases = []controlCase{
	{
		name: "F1-fixed: powershell -ep b (enum-prefix Bypass) fires",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -nop -ep b -c Get-Date`},
	},
	{
		name: "F1-fixed: powershell -ExecutionPolicy B -w h fires",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -ExecutionPolicy B -w h -c Get-Date`},
	},
	{
		name: "F1-fixed: conhost broker powershell -ep b fires (broker scope, no --headless)",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\conhost.exe`,
			CmdLine: `conhost.exe powershell -ep b -c Get-Date`},
	},
	{
		name: "F2-fixed: same-named payload outside the pe_triage repo fires (dev_scripts path-anchored)",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -ExecutionPolicy Bypass -File C:\Users\ju\evil\pe-triage-docker.ps1`},
	},
	{
		name: "C1: -ep bypass spelled out fires",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -nop -ep bypass -c Get-Date`},
	},
	{
		name: "C1b: conhost broker with --headless fires EXEC-002 even with -ep b",
		rule: "EXEC-002", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\conhost.exe`,
			CmdLine: `conhost.exe --headless powershell -ep b -c Get-Date`},
	},
	{
		name: "F3a-fixed: schtasks /tr %TEMP%\\upd.exe fires (env-var token)",
		rule: "PERSIST-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\schtasks.exe`,
			CmdLine: `schtasks.exe /create /tn OneDriveUpd /tr "%TEMP%\upd.exe" /sc onlogon /f`},
	},
	{
		name: "C2: schtasks /tr with literal ProgramData path fires",
		rule: "PERSIST-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\schtasks.exe`,
			CmdLine: `schtasks.exe /create /tn OneDriveUpd /tr C:\ProgramData\upd.exe /sc onlogon /f`},
	},
	{
		name: "F4-fixed: HKCU ...Windows NT\\CurrentVersion\\Windows\\Load fires",
		rule: "PERSIST-003", sev: event.SevCritical,
		ev: event.Event{EID: 13, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetRegKey: `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load`,
			Details:      `C:\Users\ju\Downloads\implant.exe`},
	},
	{
		name: "F4-fixed: Active Setup \\Installed Components\\{guid}\\StubPath fires",
		rule: "PERSIST-003", sev: event.SevCritical,
		ev: event.Event{EID: 13, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetRegKey: `HKEY_CURRENT_USER\Software\Microsoft\Active Setup\Installed Components\{B5F8E7C9-1A2B-4C3D-9E8F-001122334455}\StubPath`,
			Details:      `C:\Users\ju\Downloads\implant.exe`},
	},
	{
		name: "C3: Run-key write fires",
		rule: "PERSIST-003", sev: event.SevCritical,
		ev: event.Event{EID: 13, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetRegKey: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate`},
	},
	{
		name: "F5-fixed: Startup\\update.hta fires (mshta handler)",
		rule: "PERSIST-004", sev: event.SevCritical,
		ev: event.Event{EID: 11, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetFile: `C:\Users\ju\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.hta`},
	},
	{
		name: "F5-fixed: Startup\\update.jse fires (wscript encoded handler)",
		rule: "PERSIST-004", sev: event.SevCritical,
		ev: event.Event{EID: 11, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetFile: `C:\Users\ju\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.jse`},
	},
	{
		name: "C4: Startup .ps1 fires",
		rule: "PERSIST-004", sev: event.SevCritical,
		ev: event.Event{EID: 11, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetFile: `C:\Users\ju\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.ps1`},
	},
	{
		name: "C5: COM InprocServer32 hijack fires",
		rule: "PERSIST-006", sev: event.SevSuspicious,
		ev: event.Event{EID: 13, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetRegKey: `HKEY_USERS\S-1-5-21-999\Software\Classes\CLSID\{B5F8E7C9-1A2B-4C3D-9E8F-001122334455}\InprocServer32\(Default)`,
			Details:      `C:\Users\ju\Downloads\implant.exe`},
	},
	{
		name: "F7-fixed: unsigned DLL loaded from Desktop fires",
		rule: "INJECT-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 7, Image: `C:\Users\ju\Desktop\loader.exe`,
			ImageLoaded: `C:\Users\ju\Desktop\payload.dll`, Signed: "false"},
	},
	{
		name: "F7-fixed: unsigned DLL loaded from the repo tree (Documents\\GitHub\\...) fires",
		rule: "INJECT-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 7, Image: `C:\Users\ju\Documents\GitHub\leave-my-shit-alone\tests\redteam-2026-09-02b\bin\loader.exe`,
			ImageLoaded: `C:\Users\ju\Documents\GitHub\leave-my-shit-alone\tests\redteam-2026-09-02b\bin\payload.dll`, Signed: "false"},
	},
	{
		name: "C6: unsigned Temp DLL fires",
		rule: "INJECT-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 7, Image: `C:\Users\ju\AppData\Local\Temp\loader.exe`,
			ImageLoaded: `C:\Users\ju\AppData\Local\Temp\payload.dll`, Signed: "false"},
	},
	{
		name: "F8a-fixed: public-IP beacon from C:\\Users\\Public to 1.1.1.1:443 (DoH) fires NET-004",
		rule: "NET-004", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\Public\payload.exe`,
			DstIP: "1.1.1.1", DstPort: 443},
	},
	{
		name: "F8a-fixed: public-IP beacon from C:\\Users\\Public to 1.0.0.1:443 fires NET-004",
		rule: "NET-004", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\Public\payload.exe`,
			DstIP: "1.0.0.1", DstPort: 443},
	},
	{
		name: "C7: public beacon from Public dir to a NORMAL public IP fires (NET-002)",
		rule: "NET-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 3, Image: `C:\Users\Public\payload.exe`,
			DstIP: "203.0.113.9", DstPort: 443},
	},
	{
		name: "C7b: Temp image to 1.1.1.1 fires (NET-004) — image path is the only tripwire",
		rule: "NET-004", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\ju\AppData\Local\Temp\payload.exe`,
			DstIP: "1.1.1.1", DstPort: 443},
	},
	{
		name: "C8: loopback 9081 (not allowlisted) fires NET-005",
		rule: "NET-005", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\Public\payload.exe`,
			DstIP: "127.0.0.1", DstPort: 9081},
	},
	{
		name: "C9: bypass flags with NON-dev-script name fires",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -ExecutionPolicy Bypass -File C:\Users\ju\evil\payload.ps1`},
	},
	{
		// Accidental catch pinned: PERSIST-003's unanchored '\\Userinit' token
		// substring-matches any value named Userinit* — including the real
		// T1547.11 autostart value. If the token is ever tightened, this
		// control catches the coverage loss.
		name: "CU1: UserInitMprLogonScript caught by the over-broad Userinit token",
		rule: "PERSIST-003", sev: event.SevCritical,
		ev: event.Event{EID: 13, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetRegKey: `HKEY_CURRENT_USER\Environment\UserInitMprLogonScript`,
			Details:      `C:\Users\ju\Downloads\upd.bat`},
	},
	{
		// User-hive LocalServer32 hijack fires (value-list = OR semantics).
		name: "CU2: COM LocalServer32 hijack in user hive fires",
		rule: "PERSIST-006", sev: event.SevSuspicious,
		ev: event.Event{EID: 13, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetRegKey: `HKEY_USERS\S-1-5-21-999\Software\Classes\CLSID\{B5F8E7C9-1A2B-4C3D-9E8F-001122334455}\LocalServer32\(Default)`,
			Details:      `C:\Users\ju\Downloads\implant.exe`},
	},
}

func TestBypassControls(t *testing.T) {
	for _, cc := range controlCases {
		t.Run(cc.name, func(t *testing.T) {
			res := freshEngine(t).Evaluate(&cc.ev)
			ids := hitIDs(res)
			if !hasRule(ids, cc.rule) {
				t.Fatalf("CONTROL FAILED: %s must fire on %q;\ngot hits %v\nsuppressed %v (control broken => telemetry path, not the hole)",
					cc.rule, cc.name, ids, suppIDs(res))
			}
			for _, h := range res.Hits {
				if h.RuleID == cc.rule && h.Severity != cc.sev {
					t.Errorf("%s severity=%v, want %v", cc.rule, h.Severity, cc.sev)
				}
			}
		})
	}
}

func suppIDs(res *rules.Evaluation) []string {
	out := make([]string, 0, len(res.Suppressed))
	for _, s := range res.Suppressed {
		out = append(out, s.RuleID+"("+s.Reason+")")
	}
	return out
}

// TestF4AnchorKeepsDeviceChurnQuiet: the F4 fix anchors on \Windows\Load
// (not the whole CurrentVersion\Windows key) precisely so per-user Device /
// printer churn in the same key family stays quiet. If PERSIST-003 ever fires
// here, the anchor was widened past the autostart value.
func TestF4AnchorKeepsDeviceChurnQuiet(t *testing.T) {
	ev := event.Event{EID: 13, Image: `C:\Windows\System32\spoolsv.exe`,
		TargetRegKey: `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\Device`,
		Details:      `HP LaserJet 4,LPT1:`}
	if ids := hitIDs(freshEngine(t).Evaluate(&ev)); hasRule(ids, "PERSIST-003") {
		t.Errorf("per-user Device churn must stay quiet after the F4 anchor; got %v", ids)
	}
}
