// Package redteam — round-5 vectors: SPELLING class, round 3 (2026-09-03b).
//
// Five findings, engine-pinned here and live-fired from this dir (benign
// payloads only; nothing outside redteam/2026-09-03b/):
//
//   - F17 (FIXED this round): WHITESPACE-RUN token split. PowerShell's argv
//     parser (and CommandLineToArgvW) treat a run of spaces as one separator,
//     so `powershell -ep  bypass -w  h -c <payload>` (double-spaced) executed
//     with FULL Bypass/Hidden semantics while every space-form token pair in
//     EXEC-001/PERSIST-001 ('-ep bypass', '-w h', '-ExecutionPolicy B', …)
//     is a plain substring match and misses. Fixed engine-side: foldCmdLine
//     collapses whitespace runs in Engine.normalize (same choke point as the
//     F16 dash fold: rule eval, dev_scripts, dedup keying). Rows flipped
//     into controls as C17b/C17c.
//   - F18 (OPEN, pinned): full-name policy gap. The F1 fix added '-ep u'/
//     '-ep:U'/'-ExecutionPolicy:U' but NOT the full-name space form, so
//     `powershell -ExecutionPolicy Unrestricted -c <payload>` is quiet.
//     Same whack-a-mole class; the argv-parser helper is the durable fix.
//   - F19 (OPEN, pinned): EXEC-002 headless-broker gap. The rule requires
//     ['--headless', 'powershell'] — a headless conhost running cmd (or any
//     non-'powershell' child, e.g. pwsh, wscript) is fully silent, for
//     EXEC-002 AND EXEC-001 (broker scoping needs a CLI token). Hidden
//     execution via the exact incident broker, zero alerts.
//   - F20 (FIXED this round): the AiStone dev_scripts entry was an UNANCHORED
//     substring despite its comment claiming otherwise (known-limitations #1,
//     live-confirmed: repo-tree mimic ran bypass-flagged, EXEC-001 suppressed
//     via cmdline_in_dev_scripts). Now anchored on -File + the admin-owned
//     Program Files\OEM subtree (R2–R4 pattern). Row flipped into controls
//     as C20b; the real OEM task invocation is pinned quiet in
//     TestRound5LegitStaysQuiet.
//   - F21 (deployment finding, installer patched): the deployed Sysmon config
//     (SwiftOnSecurity base) EXCLUDES conhost.exe from ProcessCreate at the
//     source, so EXEC-002 has zero alerts ever. scripts/install-sysmon.ps1
//     now converts the blanket exclude into a Rule (Image AND CommandLine
//     excludes --headless — `not contains` is NOT a condition in Sysmon 15,
//     it crashes the apply; postmortem in this dir's README); takes effect
//     when the operator re-runs the installer as admin.
//
// Open rows (F18/F19) pin CURRENT posture; each has a control (same shape
// minus the hole) that MUST fire, so silence is attributed to the filter,
// not lost telemetry.
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

// ---- harness (mirrors redteam/2026-09-03/round4_vector_test.go) ----

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

func hasSupp(res *rules.Evaluation, ruleID, reason string) bool {
	for _, s := range res.Suppressed {
		if s.RuleID == ruleID && s.Reason == reason {
			return true
		}
	}
	return false
}

// ---- open bypass rows (pin CURRENT posture until fixed) ----

type bypassCase struct {
	finding        string
	name           string
	ev             event.Event
	wantZeroHits   bool   // NO rule produces a hit for this event
	wantQuietRule  string // this rule must not appear in Hits (ignored when "*")
	wantSuppRule   string // (ruleID, reason) that MUST appear in Suppressed
	wantSuppReason string
}

var bypassCases = []bypassCase{
	{
		finding: "F18", name: "full-name space form of a non-Bypass policy value (-ExecutionPolicy Unrestricted) is not a token",
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -NoProfile -ExecutionPolicy Unrestricted -c "Write-Host r5f18-marker"`},
		wantZeroHits: true,
	},
	{
		finding: "F19", name: "headless conhost running a non-powershell child (cmd) — EXEC-002 requires the 'powershell' substring",
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\conhost.exe`,
			CmdLine: `conhost.exe --headless cmd /c echo r5f19-marker`},
		wantZeroHits: true,
	},
}

// TestRound5VectorsAreQuiet pins the CURRENT silence of every open bypass
// row. A failure here means a fix landed — flip the row into the controls
// table (as F17/F17b/F20 already were).
func TestRound5VectorsAreQuiet(t *testing.T) {
	for _, bc := range bypassCases {
		t.Run(bc.finding+"/"+bc.name, func(t *testing.T) {
			res := freshEngine(t).Evaluate(&bc.ev)
			ids := hitIDs(res)
			if bc.wantZeroHits && len(res.Hits) != 0 {
				t.Errorf("expected ZERO hits (hole closed?), got %v\nsuppressed: %v", ids, suppIDs(res))
			}
			if bc.wantQuietRule != "" && bc.wantQuietRule != "*" && hasRule(ids, bc.wantQuietRule) {
				t.Errorf("expected %s QUIET, it fired\nall hits: %v", bc.wantQuietRule, ids)
			}
			if bc.wantSuppRule != "" && !hasSupp(res, bc.wantSuppRule, bc.wantSuppReason) {
				t.Errorf("expected %s suppressed(%s) documenting the mechanism; got suppressed %v",
					bc.wantSuppRule, bc.wantSuppReason, suppIDs(res))
			}
		})
	}
}

// ---- controls: fixed rows + same-shape-minus-the-hole, MUST fire ----

type controlCase struct {
	name string
	rule string
	sev  event.Severity
	ev   event.Event
}

var controlCases = []controlCase{
	{
		name: "C17: single-spaced flags fire EXEC-001 (telemetry path intact for the F17 shape)",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -NoProfile -ep bypass -w h -c "Write-Host r5f17ctl-marker"`},
	},
	{
		name: "C17b (F17 fixed): double-spaced flags now fire EXEC-001 (foldCmdLine collapses whitespace runs)",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -NoProfile -ep  bypass -w  h -c "Write-Host r5f17-marker"`},
	},
	{
		name: "C17c (F17b fixed): double-spaced full-name form now fires EXEC-001",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -NoProfile -ExecutionPolicy  Bypass -c "Write-Host r5f17b-marker"`},
	},
	{
		name: "C18: abbreviated non-Bypass policy value fires EXEC-001 ('-ep u' token) — only the full-name space form is missing",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -NoProfile -ep u -c "Write-Host r5f18ctl-marker"`},
	},
	{
		name: "C19: headless conhost running powershell fires EXEC-002 (only the non-'powershell' child evades; needs F21's telemetry fix deployed)",
		rule: "EXEC-002", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\conhost.exe`,
			CmdLine: `conhost.exe --headless powershell -NoProfile -c "Write-Host r5f19ctl-marker"`},
	},
	{
		name: "C20: same bypass-flagged -File launch WITHOUT the AiStone path substring fires EXEC-001",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\redteam\2026-09-03b\ctl_r5f20.ps1"`},
	},
	{
		name: "C20b (F20 fixed): repo-tree AiStone mimic now fires EXEC-001 (dev_scripts anchor requires -File + OEM tree)",
		rule: "EXEC-001", sev: event.SevCritical,
		ev: event.Event{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\jurij\Documents\GitHub\leave-my-shit-alone\redteam\2026-09-03b\aistoneservice\mycontrolcenter\command\logonusername.ps1"`},
	},
}

func TestRound5Controls(t *testing.T) {
	for _, cc := range controlCases {
		t.Run(cc.name, func(t *testing.T) {
			res := freshEngine(t).Evaluate(&cc.ev)
			ids := hitIDs(res)
			if !hasRule(ids, cc.rule) {
				t.Fatalf("CONTROL FAILED: %s: %s must fire;\ngot hits %v\nsuppressed %v (control broken => telemetry path, not the hole)",
					cc.name, cc.rule, ids, suppIDs(res))
			}
			for _, h := range res.Hits {
				if h.RuleID == cc.rule && h.Severity != cc.sev {
					t.Errorf("%s severity=%v, want %v", cc.rule, h.Severity, cc.sev)
				}
			}
		})
	}
}

// TestRound5LegitStaysQuiet pins the flip side of the F20 fix: the REAL
// AiStone scheduled-task invocation (-File, admin-owned Program Files\OEM
// tree, plus its cmd /c wrapper spelling) must STILL be suppressed by
// dev_scripts — the anchor tightened the trust boundary, it must not break
// the legitimate logon task (or every logon toasts EXEC-001).
func TestRound5LegitStaysQuiet(t *testing.T) {
	legit := []event.Event{
		{EID: 1, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CmdLine: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\OEM\AiStoneService\MyControlCenter\Command\LogonUserName.ps1"`},
		{EID: 1, Image: `C:\Windows\System32\cmd.exe`,
			CmdLine: `cmd.exe /c powershell -ep bypass -File C:\Program Files\OEM\aistoneservice\mycontrolcenter\command\logonusername.ps1`},
	}
	for i, ev := range legit {
		res := freshEngine(t).Evaluate(&ev)
		if hasRule(hitIDs(res), "EXEC-001") {
			t.Errorf("legit OEM AiStone task row %d must stay quiet (dev_scripts); hits %v suppressed %v", i, hitIDs(res), suppIDs(res))
		}
		if !hasSupp(res, "EXEC-001", "allowlist") {
			t.Errorf("legit OEM AiStone task row %d should be suppressed(allowlist/dev_scripts); suppressed %v", i, suppIDs(res))
		}
	}
}
