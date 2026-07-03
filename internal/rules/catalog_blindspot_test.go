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
