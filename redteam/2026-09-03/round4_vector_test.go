// Package redteam — round-4 vectors: SPELLING class, round 2 (2026-09-03).
//
// Live-fired against the post-round-3.1 daemon from redteam/lab/ (benign
// custom binaries, repo-only). Three results:
//
//   - F16 (NEW): PowerShell's console host normalizes Unicode dashes
//     (en/em/minus/…) to ASCII '-' in argv, so `–ep bypass –w h –c <payload>`
//     executes with full Bypass/Hidden semantics while every EXEC-001 token
//     (all ASCII-prefixed) misses. LIVE-CONFIRMED: payload printed, daemon
//     logged nothing for the EID1 (sibling ASCII control fired CRITICAL,
//     rec=2220107; the dash spawn's own file event rec=2220097 proves
//     telemetry). Fix: engine-side dash folding (one choke point, closes the
//     whole class) instead of token whack-a-mole.
//   - DoH-dst beacon (F8a residual, now live-confirmed): a custom binary in
//     any dir outside NET-004's list (repo trees) beaconing the allowlisted
//     DoH IPs (1.1.1.1/1.0.0.1) is fully silent (dst except on NET-002/003,
//     dir-list miss on NET-004). Control (8.8.8.8) fires NET-002/003.
//   - EXEC-004 dir-list residual (documented round 3 F13): hex-named exes
//     outside Temp|AppData|ProgramData|Users\Public (repo trees, Downloads)
//     are invisible. Control (same name in %TEMP%) fires.
//
// Constraint compliance: IN-PROCESS ONLY. Rows below marked documented-accept
// pin CURRENT posture pending an operator decision; the F16 rows flip to
// must-fire when the engine fix lands.
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

// ---- harness (mirrors redteam/2026-09-02c/custombin_vector_test.go) ----

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
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

func suppIDs(res *rules.Evaluation) []string {
	out := make([]string, 0, len(res.Suppressed))
	for _, s := range res.Suppressed {
		out = append(out, s.RuleID+"("+s.Reason+")")
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
	finding string
	name    string
	ev      event.Event
	// wantZeroHits: NO rule produces a hit for this event.
	wantZeroHits bool
	// wantQuietRule: this rule must not appear in Hits (ignored when "*").
	wantQuietRule string
	// wantSupp: (ruleID, reason) that MUST appear in Suppressed — documents
	// the mechanism (allowlist-subtracted vs Sigma-filter-level invisible).
	wantSuppRule   string
	wantSuppReason string
}

var bypassCases = []bypassCase{
	// F9 FIXED (commit "fix(allowlist): anchor known_loopback_listeners image
	// gate"): the Downloads evil-nahimic-updater row now FIRES — flipped into
	// the controls table as C9c; legit usage pinned in TestCustomBinLegitStaysQuiet.

	// F10 FIXED (commit "fix(allowlist): dev_scripts anchored to -File script
	// paths"): both rows now FIRE — flipped into the controls table as
	// C10b/C10c; the legit -File invocations are pinned in
	// TestCustomBinLegitStaysQuiet. The GCUBridge task now runs
	// scripts\gcubridge-watchdog.ps1 via -File (operator re-registration
	// pending: until then the task safely alerts).

	// F11 FIXED (commit "fix(rules): CONFIG-001 filter_sentinel anchored"): the
	// Downloads-renamed sentinel.exe row now FIRES — flipped into the controls
	// table as C11b.

	// F12 FIXED (commit "fix(rules): NET-005 recognizes ::ffff:127.x loopback
	// spelling"): the mapped-spelling row now FIRES NET-005 — flipped into the
	// controls table as C12c. Still unreachable live on current Winsock
	// (v4-mapped connect → WSAEADDRNOTAVAIL, probe-verified round 3); the row
	// pins the spelling class is closed at the engine level.

	// F13 FIXED (commit "fix(rules): EXEC-004 + INJECT-002 cover Users\Public"):
	// both Public rows now FIRE — flipped into the controls table as C13c/C13d.

	// F15 FIXED (commit "fix(allowlist): Tier-1 trust pinned to the system
	// drive"): both D:\ plant rows now FIRE — flipped into the controls table
	// as C15c/C15d; legit C:\Program Files usage pinned in
	// TestCustomBinLegitStaysQuiet.
}

// TestCustomBinVectorsAreQuiet pins the CURRENT silence of every bypass row.
// A failure here means a fix landed — flip the row into the controls table.
func TestCustomBinVectorsAreQuiet(t *testing.T) {
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
			if bc.wantSuppRule != "" {
				found := false
				for _, s := range res.Suppressed {
					if s.RuleID == bc.wantSuppRule && s.Reason == bc.wantSuppReason {
						found = true
					}
				}
				if !found {
					t.Errorf("expected %s suppressed(%s) documenting the mechanism; got suppressed %v",
						bc.wantSuppRule, bc.wantSuppReason, suppIDs(res))
				}
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
		name: "C9: same loopback chat WITHOUT nahimic in the name fires NET-005 (F9 is name-only)",
		rule: "NET-005", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\updater.exe`,
			DstIP: "127.0.0.1", DstPort: 9080},
	},
	{
		name: "C9b: nahimic-named binary on ANY OTHER port fires NET-005 (name alone must not except)",
		rule: "NET-005", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\nahimic-updater.exe`,
			DstIP: "127.0.0.1", DstPort: 9081},
	},
	{
		name: "C9c (F9 fixed): nahimic-named binary OUTSIDE the install roots chats on :9080 — NET-005 fires (image gate is path-anchored)",
		rule: "NET-005", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\evil-nahimic-updater.exe`,
			DstIP: "127.0.0.1", DstPort: 9080},
	},
	{
		name: "C10: the same piggyback cmdline minus the GCUBridge marker fires EXEC-001 (telemetry path intact)",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -ep bypass -w h -c "Write-Host probe-ok"`},
	},
	{
		name: "C10b (F10 fixed): piggyback payload after the GCUBridge marker now fires EXEC-001 (marker no longer a dev_scripts anchor)",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -ep bypass -w h -c "Get-Service -Name 'GCUBridge'; Write-Host probe-ok"`},
	},
	{
		name: "C10c (F10 fixed): mentioning the pe-triage path as an inert string (IEX) now fires EXEC-001 (anchor requires -File)",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -ep bypass -c "IEX(gc C:\pe_triage\scripts\pe-triage-docker.ps1)"`},
	},
	{
		name: "C11: the same config write from a non-sentinel name fires CONFIG-001",
		rule: "CONFIG-001", sev: event.SevCritical,
		ev: event.Event{EID: 11, Image: `C:\Users\ju\Downloads\tamper.exe`,
			TargetFile: `C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\config\allowlist.json`},
	},
	{
		name: "C11b (F11 fixed): renamed sentinel.exe in Downloads writing the real config now fires CONFIG-001 (name-trust is path-anchored)",
		rule: "CONFIG-001", sev: event.SevCritical,
		ev: event.Event{EID: 11, Image: `C:\Users\ju\Downloads\sentinel.exe`,
			TargetFile: `C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\config\allowlist.json`},
	},
	{
		name: "C12a: plain 127.0.0.1 loopback fires NET-005 (only the v4-mapped spelling evades)",
		rule: "NET-005", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\probe.exe`,
			DstIP: "127.0.0.1", DstPort: 7777},
	},
	{
		name: "C12b: IPv6-shaped public dst flows through the engine and fires NET-002 (not an IPv6 telemetry gap)",
		rule: "NET-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\probe.exe`,
			DstIP: "2001:db8::1", DstPort: 443},
	},
	{
		name: "C12c (F12 fixed): ::ffff:127.0.0.1:7777 (v4-mapped loopback spelling) now fires NET-005",
		rule: "NET-005", sev: event.SevCritical,
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\probe.exe`,
			DstIP: "::ffff:127.0.0.1", DstPort: 7777},
	},
	{
		name: "C13a: the same hex-named exe in Temp fires EXEC-004 (dir list, not name, is the hole)",
		rule: "EXEC-004", sev: event.SevSuspicious,
		ev: event.Event{EID: 1, Image: `C:\Users\ju\AppData\Local\Temp\deadbeefcafe.exe`, CmdLine: `"C:\Users\ju\AppData\Local\Temp\deadbeefcafe.exe" `},
	},
	{
		name: "C13b: the same unsigned DLL from Desktop fires INJECT-002",
		rule: "INJECT-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 7, Image: `C:\Users\ju\Documents\host.exe`,
			ImageLoaded: `C:\Users\ju\Desktop\payload.dll`, Signed: "false"},
	},
	{
		name: "C13c (F13 fixed): hex-named exe in C:\\Users\\Public now fires EXEC-004",
		rule: "EXEC-004", sev: event.SevSuspicious,
		ev: event.Event{EID: 1, Image: `C:\Users\Public\deadbeefcafe.exe`, CmdLine: `"C:\Users\Public\deadbeefcafe.exe" `},
	},
	{
		name: "C13d (F13 fixed): unsigned DLL sideloaded from C:\\Users\\Public now fires INJECT-002",
		rule: "INJECT-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 7, Image: `C:\Users\ju\Documents\host.exe`,
			ImageLoaded: `C:\Users\Public\payload.dll`, Signed: "false"},
	},
	{
		name: "C15a: the same beacon from the USER's Downloads fires NET-002 (trust is the D:\\Program Files path, nothing else)",
		rule: "NET-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\ffupdate.exe`,
			DstIP: "203.0.113.9", DstPort: 443},
	},
	{
		name: "C15b: the same Run-key write from Downloads fires PERSIST-003",
		rule: "PERSIST-003", sev: event.SevCritical,
		ev: event.Event{EID: 13, Image: `C:\Users\ju\Downloads\implant.exe`,
			TargetRegKey: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate`},
	},
	{
		name: "C15c (F15 fixed): D:\\Program Files plant (user-creatable on a data drive) beacons a public IP — Tier-1 no longer trusts non-system volumes, NET-002 fires",
		rule: "NET-002", sev: event.SevSuspicious,
		ev: event.Event{EID: 3, Image: `D:\Program Files\Mozilla Firefox\ffupdate.exe`,
			DstIP: "203.0.113.9", DstPort: 443},
	},
	{
		name: "C15d (F15 fixed): the same D:\\ plant writes an HKCU Run key — PERSIST-003 fires",
		rule: "PERSIST-003", sev: event.SevCritical,
		ev: event.Event{EID: 13, Image: `D:\Program Files\Mozilla Firefox\ffupdate.exe`,
			TargetRegKey: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate`},
	},
}

func TestCustomBinControls(t *testing.T) {
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

// TestTier2GateBlocksCustomBinary pins the Tier-2 (hash_gated_path) gate the
// way an actual custom binary meets it: planted at a Tier-2 pattern path with
// a SHA256, NO valid vendor signature. It must stay untrusted — behavioral
// rules fire. The second half pins what a validly-signed vendor binary gets
// (path AND signature = trust), via a fake PinnedVerifier, so the gate's
// semantics — not just its absence — are on record. Note the real verifier
// (internal/sigverify) runs WinVerifyTrustEx FIRST: a self-signed cert with a
// spoofed "Python Software Foundation" subject fails chain validation before
// any subject comparison, so subject spoofing does not reopen this.
func TestTier2GateBlocksCustomBinary(t *testing.T) {
	// Behavioral shape: HKCU Run-key write. PERSIST-003's only except is
	// image_in_allowlist, so this isolates the Tier-2 gate. (A NET-002 beacon
	// would NOT work here: the .local\bin\claude.exe path is ALSO in
	// dev_tool_paths, whose image_in_dev_tools except NET-quiets it by design
	// — that is the documented Bypass-B interim posture, not Tier-2.)
	mimic := &event.Event{EID: 13, Image: `C:\Users\ju\.local\bin\claude.exe`,
		TargetRegKey: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate`,
		Hashes:       map[string]string{"SHA256": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}}

	// (a) no verifier injected / signature fails: fail closed — PERSIST-003 fires.
	res := freshEngine(t).Evaluate(mimic)
	if !hasRule(hitIDs(res), "PERSIST-003") {
		t.Errorf("unsigned Tier-2 mimic must stay untrusted: PERSIST-003 should FIRE; hits %v suppressed %v", hitIDs(res), suppIDs(res))
	}

	// (b) valid signature by an allowed vendor: path+sig = trust (suppressed).
	al := loadRealAllowlist(t)
	al.SetSigVerifier(fakePinned{ok: true})
	eng, err := rules.New(loadRealCatalog(t), al, newMemDedup())
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	res = eng.Evaluate(mimic)
	if len(res.Hits) != 0 {
		t.Errorf("signed-by-allowed-vendor binary at a Tier-2 path is trusted BY DESIGN (if this row breaks, the gate semantics changed); hits %v", hitIDs(res))
	}
	if !hasSupp(res, "PERSIST-003", "allowlist") {
		t.Errorf("expected PERSIST-003 suppressed(allowlist) for the signed Tier-2 binary; suppressed %v", suppIDs(res))
	}
}

type fakePinned struct{ ok bool }

func (f fakePinned) VerifyAndHash(path string, allowedSigners []string) (bool, string) {
	return f.ok, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
}

func hasSupp(res *rules.Evaluation, ruleID, reason string) bool {
	for _, s := range res.Suppressed {
		if s.RuleID == ruleID && s.Reason == reason {
			return true
		}
	}
	return false
}

type r4Case struct {
	name string
	ev   event.Event
	// wantZeroHits: NO rule produces a hit for this event.
	wantZeroHits bool
	// wantHit: this rule MUST appear in Hits.
	wantHit string
	// wantQuietRule: this rule must NOT appear in Hits ("" = ignore).
	wantQuietRule string
}

// ---- the vector table ----

// TestRound4Vectors pins round-4 posture: F16 rows are FLIPPED CONTROLS
// (must fire — the engine folds unicode dashes before matching); the
// DoH/EXEC-004 rows pin the documented-accept residuals (quiet = posture,
// with firing controls).
func TestRound4VectorsAreQuiet(t *testing.T) {
	cases := []r4Case{
		// F16 FIXED — engine folds unicode dashes to '-' before matching, so
		// the full-bypass spelling now hits EXEC-001 exactly like the ASCII
		// form (controls: the DoH/EXEC-004 control rows below still fire).
		{
			name: "F16 fixed: en-dash flags — EXEC-001 fires (was: silent)",
			ev: event.Event{EID: 1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: "powershell.exe \u2013ep bypass \u2013w h \u2013c \"Write-Host p\""},
			wantHit: "EXEC-001",
		},
		{
			name: "F16 fixed: em-dash form — EXEC-001 fires",
			ev: event.Event{EID: 1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: "powershell.exe \u2014ep bypass \u2014w h \u2014c \"Write-Host p\""},
			wantHit: "EXEC-001",
		},
		{
			name: "F16 fixed: minus-sign form (U+2212) — EXEC-001 fires",
			ev: event.Event{EID: 1,
				Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CmdLine: "powershell.exe \u2212ep bypass \u2212w h \u2212c \"Write-Host p\""},
			wantHit: "EXEC-001",
		},

		// F16 sibling: the same spelling against the dev_scripts -File anchors
		// — '–file <real watchdog path>' folds to the legit anchor, so the real
		// invocation stays suppressed (pinned in TestRound4LegitStaysQuiet).

		// DoH-dst beacon — F8a residual, live-confirmed. Documented-accept
		// posture: pinned here so any posture change flips this row loudly.
		{
			name: "DoH residual: custom repo binary beacons 1.1.1.1:443 — fully silent (dst allowlist + NET-004 dir-list miss)",
			ev: event.Event{EID: 3,
				Image: `C:\Users\jurij\Documents\Github\leave-my-shit-alone\redteam\lab\evil.exe`,
				DstIP: "1.1.1.1", DstPort: 443},
			wantQuietRule: "NET-002",
			wantZeroHits:  true,
		},
		// control — non-allowlisted dst must fire NET-002 (telemetry intact).
		{
			name: "DoH control: same binary beacons 8.8.8.8:53 — NET-002 fires",
			ev: event.Event{EID: 3,
				Image: `C:\Users\jurij\Documents\Github\leave-my-shit-alone\redteam\lab\evil.exe`,
				DstIP: "8.8.8.8", DstPort: 53},
			wantHit: "NET-002",
		},

		// EXEC-004 dir-list residual (F13 note) — hex-named exe in a repo tree.
		{
			name: "EXEC-004 residual: hex-named exe in repo tree — silent (dir list misses repo trees)",
			ev: event.Event{EID: 1,
				Image:   `C:\Users\jurij\Documents\Github\leave-my-shit-alone\redteam\lab\cafe123456.exe`,
				CmdLine: `cafe123456.exe`},
			wantQuietRule: "EXEC-004",
			wantZeroHits:  true,
		},
		// control — same name in %TEMP% must fire EXEC-004 (mirrors C13a).
		{
			name: "EXEC-004 control: hex-named exe in %TEMP% — EXEC-004 fires",
			ev: event.Event{EID: 1,
				Image:   `C:\Users\jurij\AppData\Local\Temp\cafe123456.exe`,
				CmdLine: `cafe123456.exe`},
			wantHit: "EXEC-004",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := freshEngine(t).Evaluate(&tc.ev)
			hits := hitIDs(res)
			if tc.wantHit != "" && !hasRule(hits, tc.wantHit) {
				t.Fatalf("expected %s to fire, hits=%v supp=%v", tc.wantHit, hits, suppIDs(res))
			}
			if tc.wantQuietRule != "" && hasRule(hits, tc.wantQuietRule) {
				t.Fatalf("expected %s quiet (vector row), hits=%v supp=%v", tc.wantQuietRule, hits, suppIDs(res))
			}
			if tc.wantZeroHits && len(hits) != 0 {
				t.Fatalf("expected zero hits, hits=%v supp=%v", hits, suppIDs(res))
			}
		})
	}
}

// TestRound4LegitStaysQuiet pins that the F16 folding did not over-tighten:
// a legit dev-script invocation spelled with a unicode dash still matches its
// dev_scripts anchor (the fold makes it IDENTICAL to the ASCII form, by
// design — PS saw the same argv either way).
func TestRound4LegitStaysQuiet(t *testing.T) {
	ev := event.Event{EID: 1,
		Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine: "powershell.exe \u2013WindowStyle Hidden \u2013ep bypass \u2013File C:\\Users\\jurij\\Documents\\GitHub\\leave-my-shit-alone\\scripts\\gcubridge-watchdog.ps1"}
	res := freshEngine(t).Evaluate(&ev)
	if len(res.Hits) != 0 {
		t.Fatalf("legit -File watchdog (unicode dash) must stay quiet, hits=%v", hitIDs(res))
	}
	if !hasSupp(res, "EXEC-001", "allowlist") {
		t.Fatalf("expected EXEC-001 suppressed(allowlist); suppressed=%v", suppIDs(res))
	}
}
