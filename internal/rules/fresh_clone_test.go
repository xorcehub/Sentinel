package rules

import (
	"path/filepath"
	"testing"

	"sentinel/internal/allowlist"
	"sentinel/internal/catalog"
	"sentinel/internal/event"
	"sentinel/internal/sigmaeval"
)

// A fresh clone has no rules.d/local/ and runs with the empty tracked
// config/allowlist.json. It must not inherit the development box's tuning:
// every shape the worked-example overlays quiet must FIRE on the shipped
// catalog alone. If one of these goes quiet, per-box tuning leaked back into
// rules.d/*.yml.

func freshCloneEngine(t *testing.T) *Engine {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "rules.d")
	data, n, err := catalog.Read(dir)
	if err != nil {
		t.Fatalf("read shipped catalog: %v", err)
	}
	if n != 0 {
		t.Fatalf("shipped catalog read %d overlay files, want 0", n)
	}
	rs, err := sigmaeval.Load(data)
	if err != nil {
		t.Fatalf("load shipped catalog: %v", err)
	}
	for _, r := range rs {
		if r.OverlayCount() != 0 {
			t.Fatalf("%s: shipped rules.d/*.yml carries %d overlay(s); per-box tuning belongs in rules.d/local/", r.XID, r.OverlayCount())
		}
	}
	al, err := allowlist.Load(filepath.Join(repoRoot(t), "config", "allowlist.json"))
	if err != nil {
		t.Fatalf("load default allowlist: %v", err)
	}
	return mustNewEngine(t, rs, al)
}

// tunedQuietShapes are the events the example overlays exist to quiet.
var tunedQuietShapes = []struct {
	name, rule string
	ev         event.Event
}{
	{"Cursor agent bridge", "EXEC-001", event.Event{EID: 1,
		Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ParentImage: `C:\Users\jurij\AppData\Local\Programs\cursor\cursor.exe`,
		CmdLine:     `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-ee8f8c48-f92b-4ac2-9d0f-ea3b35e93f40.ps1`}},
	{"Cursor agent bridge", "PERSIST-001", event.Event{EID: 1,
		Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ParentImage: `C:\Users\jurij\AppData\Local\Programs\cursor\cursor.exe`,
		CmdLine:     `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-ee8f8c48-f92b-4ac2-9d0f-ea3b35e93f40.ps1`}},
	{"Python signer-discovery helper", "EXEC-001", event.Event{EID: 1,
		Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ParentImage: `C:\Users\jurij\AppData\Local\Programs\Python\python314\python.exe`,
		CmdLine:     `powershell -NoProfile -EncodedCommand RwBlAHQALQBBAHUAdABoAGUAbgB0AGkAYwBvAGQAZQBTAGkAZwBuAGEAdAB1AHIAZQAgAC0ATABpAHQAZQByAGEAbABQAGEAdABoACAAQAAoACcAQwA6AFwAVwBpAG4AZABvAHcAcwA=`}},
	{"Claude Code launcher cmd", "EXEC-001", event.Event{EID: 1, Image: sysCmd, ParentImage: claudeExe, CmdLine: launcherCmd}},
	{"Claude Code launcher cmd", "PERSIST-001", event.Event{EID: 1, Image: sysCmd, ParentImage: claudeExe, CmdLine: launcherCmd}},
	{"Claude Code launcher powershell", "EXEC-001", event.Event{EID: 1, Image: sysPS, ParentImage: sysCmd, ParentCmdLine: launcherCmd, CmdLine: launcherPS}},
	{"Cursor ConPTY host", "EXEC-002", event.Event{EID: 1,
		Image:       `C:\Windows\system32\conhost.exe`,
		ParentImage: `C:\Users\jurij\AppData\Local\Programs\cursor\cursor.exe`,
		CmdLine:     `\?\C:\WINDOWS\system32\conhost.exe --headless --width 127 --height 24 --signal 0xcf8 --server 0xcbc`}},
	{"Nahimic DataSystemCOM re-registration", "PERSIST-006", event.Event{EID: 13,
		Image:        `C:\Windows\System32\NahimicService.exe`,
		TargetRegKey: `HKCR\CLSID\{1FC71449-ACEC-420D-A3E9-7A0FC630926E}\InprocServer32\(Default)`,
		Details:      `C:\ProgramData\A-Volute\A-Volute.Nahimic\Modules\Regular\x64\DataSystemCOM.dll`}},
}

func TestFreshCloneRunsTunedShapesArmed(t *testing.T) {
	for _, s := range tunedQuietShapes {
		ev := s.ev
		if ids := hitRuleIDs(freshCloneEngine(t).Evaluate(&ev)); !containsRule(ids, s.rule) {
			t.Errorf("fresh clone: %s must fire %s (no overlays); got %v", s.name, s.rule, ids)
		}
	}
}

// The same shapes are quiet on the tuned box (shipped catalog + example
// overlays + example allowlist), proving the overlays carry the tuning.
func TestTunedBoxQuietsShapesViaOverlays(t *testing.T) {
	for _, s := range tunedQuietShapes {
		ev := s.ev
		if ids := hitRuleIDs(realEngine(t).Evaluate(&ev)); containsRule(ids, s.rule) {
			t.Errorf("tuned box: %s should be quiet for %s; got %v", s.name, s.rule, ids)
		}
	}
}
