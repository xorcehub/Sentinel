// Package redteam — round-3 evasion vectors: CUSTOM-BINARY shapes against the
// REAL catalog (rules.d/*.yml) + REAL allowlist (config/allowlist.json) + the
// REAL engine.
//
// Rounds 1-2 probed event SPELLING (cmdline tokens, path anchors). This round
// probes what an attacker who ships their own binary gains: self-chosen NAME,
// SELF-CHOSEN PATH, and loopback/socket SPELLINGS only a custom binary can
// produce. Found by reading allowlist.go (unanchored compiled regexes:
// known_loopback_listeners image gates, dev_scripts cmdline anchors) and
// rules.d filter selections (CONFIG-001 name-trust, EXEC-004/INJECT-002 dir
// lists, trusted_binaries Tier-1 `^[a-z]:` drive-agnostic prefixes).
//
// Every bypass row asserts SILENCE (current, broken behavior); every bypass
// has a control row (same event, one deviation) that MUST fire, so quiet is
// attributable to the hole and not to lost telemetry (round-1 doctrine).
// Tier-2 (hash_gated_path + sigverify) is pinned fail-closed for custom
// binaries in TestTier2GateBlocksCustomBinary.
//
// IN-PROCESS ONLY: no registry writes, no files outside this directory, no
// network. Optional live-fire probe: probe-bin.go (loopback/echo only).
//
// When a fix lands, its quiet row starts failing: flip it into the controls
// table, like rounds 1-2 did.
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

// ---- harness (mirrors tests/redteam-2026-09-02b/evasion_vector_test.go) ----

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

	// F10: dev_scripts entries compile to UNANCHORED (?i) substrings of the raw
	// cmdline. 'Get-Service -Name 'GCUBridge'' matches ANYWHERE in a cmdline,
	// so appending arbitrary payload after the marker (or mentioning a
	// dev-script path as an argument) suppresses EXEC-001 for the whole
	// bypass-flagged launch. The scheduled task this was written for uses the
	// marker as the ENTIRE -Command payload; the except cannot tell.
	{
		finding: "F10",
		name:    "powershell -ep bypass -w h piggybacks payload after the GCUBridge dev_scripts marker — EXEC-001 suppressed",
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -ep bypass -w h -c "Get-Service -Name 'GCUBridge'; Write-Host probe-ok"`},
		wantZeroHits:   true,
		wantQuietRule:  "EXEC-001",
		wantSuppRule:   "EXEC-001",
		wantSuppReason: "allowlist",
	},
	{
		finding: "F10",
		name:    "same class via the pe-triage path anchor: mention the trusted dev-script path as a string, run IEX — EXEC-001 suppressed",
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -ep bypass -c "IEX(gc C:\pe_triage\scripts\pe-triage-docker.ps1)"`},
		wantZeroHits:   true,
		wantQuietRule:  "EXEC-001",
		wantSuppRule:   "EXEC-001",
		wantSuppReason: "allowlist",
	},

	// F11 FIXED (commit "fix(rules): CONFIG-001 filter_sentinel anchored"): the
	// Downloads-renamed sentinel.exe row now FIRES — flipped into the controls
	// table as C11b.

	// F12: NET-005's dst regex anchors on ^(127\.|::1|0:0:0:0:0:0:0:1) — the
	// IPv4-MAPPED IPv6 spelling ::ffff:127.0.0.1 starts with '::f' and misses.
	// NET-002/003 DO see it, but allowed_destinations' 127.0.0.0/8 excepts it:
	// net.IPNet.Contains calls To4(), and ::ffff:127.0.0.1 IS 127.0.0.1 there.
	// Only a custom binary produces this dst spelling (dial AF_INET6 with a
	// v4-mapped loopback address). Whether Sysmon RENDERS that spelling is the
	// live probe's job (probe-bin.go loop6); this row pins the engine
	// semantics: IF such an event arrives, the catalog is fully silent.
	{
		finding: "F12",
		name:    "loopback connect to ::ffff:127.0.0.1:7777 (v4-mapped IPv6 spelling) — NET-005 regex misses, NET-002/003 dst-allowlisted: zero hits",
		ev: event.Event{EID: 3, Image: `C:\Users\ju\Downloads\probe.exe`,
			DstIP: "::ffff:127.0.0.1", DstPort: 7777},
		wantZeroHits:  true,
		wantQuietRule: "*",
	},

	// F13: the F8a fix added Users\Public to NET-004's dir list only. The
	// sibling rules with the same dir-list class kept their old lists:
	// EXEC-004 still knows only (Temp|AppData|ProgramData), INJECT-002 only
	// (...|Downloads|Desktop|Documents). C:\Users\Public is world-writable —
	// the exact dir F8a called out — and custom binaries choose their own
	// name/dir freely. (Downloads and repo trees miss EXEC-004 the same way.)
	{
		finding: "F13",
		name:    "hex-named custom binary runs from C:\\Users\\Public — EXEC-004 silent (Public not in its dir list)",
		ev: event.Event{EID: 1, Image: `C:\Users\Public\deadbeefcafe.exe`, CmdLine: `"C:\Users\Public\deadbeefcafe.exe" `},
		wantZeroHits:  true,
		wantQuietRule: "EXEC-004",
	},
	{
		finding: "F13",
		name:    "unsigned DLL sideloaded from C:\\Users\\Public — INJECT-002 silent (Public not in its dir list)",
		ev: event.Event{EID: 7, Image: `C:\Users\ju\Documents\host.exe`,
			ImageLoaded: `C:\Users\Public\payload.dll`, Signed: "false"},
		wantZeroHits:  true,
		wantQuietRule: "INJECT-002",
	},

	// F15 (headline): trusted_binaries Tier-1 path patterns are `^[a-z]:\\program files\\...`
	// — the drive letter is a WILDCARD. The tier's premise is "Program Files is
	// admin-owned"; that is only true on the system drive. On any second data
	// drive (this box has D:) a USER creates D:\Program Files\Mozilla Firefox\
	// unprivileged, plants a custom exe, and inherits FULL behavioral trust:
	// every rule with `except: image_in_allowlist` goes quiet for it. Same
	// class: D:\ProgramData\Microsoft\Windows Defender\...\msmpeng.exe on a
	// data volume is a user-created tree matching the Defender pattern.
	{
		finding: "F15",
		name:    "custom binary planted at D:\\Program Files\\Mozilla Firefox\\ (user-creatable on a data drive) beacons a public IP — Tier-1 trusted, NET-002/003 suppressed",
		ev: event.Event{EID: 3, Image: `D:\Program Files\Mozilla Firefox\ffupdate.exe`,
			DstIP: "203.0.113.9", DstPort: 443},
		wantZeroHits:   true,
		wantQuietRule:  "*",
		wantSuppRule:   "NET-002",
		wantSuppReason: "allowlist",
	},
	{
		finding: "F15",
		name:    "same D:\\ plant writes an HKCU Run key — PERSIST-003 suppressed(allowlist): persistence invisible",
		ev: event.Event{EID: 13, Image: `D:\Program Files\Mozilla Firefox\ffupdate.exe`,
			TargetRegKey: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate`},
		wantZeroHits:   true,
		wantQuietRule:  "*",
		wantSuppRule:   "PERSIST-003",
		wantSuppReason: "allowlist",
	},
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

// TestCustomBinLegitStaysQuiet pins that each fix did NOT over-tighten: the
// legitimate usage the eased/anchored entry was written for still suppresses.
func TestCustomBinLegitStaysQuiet(t *testing.T) {
	legitCases := []struct {
		name string
		ev   event.Event
		supp string // rule that must appear suppressed(allowlist)
	}{
		{
			name: "F9 legit: the real AppData nhnotifsys nahimic component on :9080 stays suppressed",
			ev: event.Event{EID: 3, Image: `c:\users\ju\appdata\local\nhnotifsys\nahimic\module.exe`,
				DstIP: "127.0.0.1", DstPort: 9080},
			supp: "NET-005",
		},
	}
	for _, lc := range legitCases {
		t.Run(lc.name, func(t *testing.T) {
			res := freshEngine(t).Evaluate(&lc.ev)
			if len(res.Hits) != 0 {
				t.Errorf("legit usage must stay quiet, got hits %v (suppressed %v)", hitIDs(res), suppIDs(res))
			}
			if !hasSupp(res, lc.supp, "allowlist") {
				t.Errorf("expected %s suppressed(allowlist); suppressed %v", lc.supp, suppIDs(res))
			}
		})
	}
}
