package allowlist

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"sentinel/internal/event"
)

func writeTempJSONC(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "allowlist.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

const sampleJSONC = `{
  "trusted_binaries": {
    "sha256": ["ABC123DEF456"],
    "path": [
      "\\\\program files\\\\mozilla firefox\\\\.*\\.exe$",
      "\\\\windows\\\\system32\\\\.*\\.exe$"
    ]
  },
  "allowed_destinations": {
    "cidr": [
      "127.0.0.0/8",          // loopback
      "10.0.0.0/8",
      "1.1.1.1/32"            // cloudflare dns
    ]
  },
  "known_loopback_listeners": [
    "127.0.0.1:9080"          // NahimicService
  ],
  "dev_tool_paths": {
    "path": [
      "\\\\users\\\\user01\\\\go\\\\bin\\\\.*\\.exe$"
    ]
  }
}`

func TestLoadAndChecks(t *testing.T) {
	a, err := Load(writeTempJSONC(t, sampleJSONC))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// SHA256 trust
	if !a.ImageTrusted(&event.Event{Hashes: map[string]string{"SHA256": "abc123def456"}}) {
		t.Error("SHA256 (case-insensitive) should be trusted")
	}
	if a.ImageTrusted(&event.Event{Hashes: map[string]string{"SHA256": "nope"}}) {
		t.Error("unknown SHA256 should not be trusted")
	}

	// Path trust (normalized lower)
	if !a.ImageTrusted(&event.Event{Image: `C:\Windows\System32\cmd.exe`}) {
		t.Error("system32 path should be trusted via pattern")
	}
	if a.ImageTrusted(&event.Event{Image: `C:\Users\user01\Downloads\evil.exe`}) {
		t.Error("downloads path should not be trusted")
	}

	// dev tools
	if !a.ImageInDevTools(`/c/Users/user01/go/bin/foo.exe`) { // git-bash form
		t.Error("go/bin path (drive-slash form) should match dev tools")
	}
	if a.ImageInDevTools(`C:\Users\user01\Downloads\evil.exe`) {
		t.Error("downloads is not a dev tool path")
	}

	// CIDR
	if !a.DstInCIDR("127.0.0.1") {
		t.Error("127.0.0.1 in 127.0.0.0/8")
	}
	if !a.DstInCIDR("10.5.5.5") {
		t.Error("10.5.5.5 in 10.0.0.0/8")
	}
	if !a.DstInCIDR("1.1.1.1") {
		t.Error("1.1.1.1 /32")
	}
	if a.DstInCIDR("8.8.8.8") {
		t.Error("8.8.8.8 not allowed")
	}
	if a.DstInCIDR("garbage") {
		t.Error("garbage ip should not match")
	}

	// known loopback
	if !a.DstIsKnownLoopback("127.0.0.1", 9080) {
		t.Error("127.0.0.1:9080 is a known loopback")
	}
	if a.DstIsKnownLoopback("127.0.0.1", 58172) {
		t.Error("127.0.0.1:58172 should NOT be known (that's the broker)")
	}
}

// Confirm the JSONC comment stripper doesn't corrupt string contents.
func TestStripJSONCPreservesStrings(t *testing.T) {
	in := []byte(`{"a": "// not a comment", "b": 1 // real comment
}`)
	out := stripJSONC(in)
	// the in-string "// not a comment" must survive
	if !regexp.MustCompile(`"// not a comment"`).Match(out) {
		t.Errorf("in-string // corrupted: %s", out)
	}
	// the trailing real comment must be gone
	if regexp.MustCompile(`real comment`).Match(out) {
		t.Errorf("real comment not stripped: %s", out)
	}
}

// Sanity: net.IPNet.Contains behaves as the engine assumes.
// TestPathPatternMatchesSingleAndNested is the regression for the escaping bug that
// made allowlist path patterns match NOTHING in production: the buggy JSONC tail
// `\\.exe$` (4 backslashes -> regex `\.exe$`) requires a backslash immediately
// before `.exe`, which single-level paths (system32\cmd.exe) lack. Correct tail
// is `\.exe$` (2 backslashes -> regex `\.exe$` = literal dot). Both single-level
// AND nested paths must match after the fix.
//
// The JSONC fixture below uses a Go RAW STRING (backticks) so each backslash is
// literal — no Go-escape counting. JSONC convention: path separator = 4
// backslashes (-> regex `\\` -> literal `\`); literal dot before exe = 2
// backslashes (-> regex `\.`).
func TestPathPatternMatchesSingleAndNested(t *testing.T) {
	// Regression for the escaping bug that made allowlist path patterns match
	// NOTHING in production: the buggy JSONC tail `\\.exe$` (4 backslashes ->
	// regex `\\.exe$`) requires a backslash immediately before `.exe`, which
	// single-level paths (system32\cmd.exe) lack. Correct tail is `\.exe$`
	// (2 backslashes -> regex `\.exe$` = literal dot). Both single-level AND
	// nested paths must match after the fix.
	//
	// Fixture uses a Go RAW STRING (backticks) so backslashes are literal — no
	// Go-escape counting. JSONC convention: separator = 4 backslashes (regex `\\`),
	// literal dot = 2 backslashes (regex `\.`). Both patterns are in
	// trusted_binaries so one ImageTrusted call exercises the tail fix for both.
	const jsonc = `{
  "trusted_binaries": {
    "path": [
      "\\\\windows\\\\system32\\\\.*\\.exe$",
      "\\\\users\\\\user01\\\\go\\\\bin\\\\.*\\.exe$"
    ]
  }
}`

	a, err := Compile([]byte(jsonc))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cases := []struct {
		name  string
		image string
		want  bool
	}{
		{"system32 single-level", `C:\Windows\System32\cmd.exe`, true},
		{"system32 nested", `C:\Windows\System32\wbem\wmic.exe`, true},
		{"go bin (drive-slash form)", `/c/Users/user01/go/bin/foo.exe`, true},
		{"downloads (not trusted)", `C:\Users\user01\Downloads\evil.exe`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := a.ImageTrusted(&event.Event{Image: c.image})
			if got != c.want {
				t.Errorf("ImageTrusted(%q)=%v want %v (pattern regression)", c.image, got, c.want)
			}
		})
	}
}

func TestCIDRContainsSanity(t *testing.T) {
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	if !n.Contains(net.ParseIP("127.0.0.1")) {
		t.Fatal("cidr sanity")
	}
}

// TestDevToolPathRegexCompiles is the regression for the malformed-regex bug:
// the sample JSONC had `\go` (2 source backslashes -> regex `\g` -> invalid
// escape). Every path segment must use 4 source backslashes (-> regex `\\`
// = literal backslash). This test fails to COMPILE/LOAD the allowlist if any
// path pattern is malformed, so backslash mistakes surface here, not at runtime.
func TestDevToolPathRegexCompiles(t *testing.T) {
	a, err := Load(writeTempJSONC(t, sampleJSONC))
	if err != nil {
		t.Fatalf("allowlist failed to load (likely a malformed path regex): %v", err)
	}
	if a == nil {
		t.Fatal("nil allowlist")
	}
}

// TestProductionAllowlistDoesNotTrustLOLBins is the regression guard for the
// design bug where the starter allowlist blanket-trusted \windows\system32\.*.exe,
// which silently disabled EVERY behavior rule (EXEC-001, PERSIST-001, EVADE-001,
// CRED-002, INJECT-*) for the exact LOLBin actors the incident used. The
// --self-test passed because it uses its own embedded allowlist; this test loads
// the REAL config/allowlist.json and asserts the LOLBins stay untrusted while
// benign Windows binaries remain trusted (so NET-002 stays quiet).
//
// If this test fails, someone re-added a broad System32 glob (or added a LOLBin
// to the benign list) - review before committing.
func TestProductionAllowlistDoesNotTrustLOLBins(t *testing.T) {
	// Locate config/allowlist.json by walking up from this test file.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	var prodPath string
	for i := 0; i < 6; i++ {
		cand := filepath.Join(dir, "config", "allowlist.json")
		if _, err := os.Stat(cand); err == nil {
			prodPath = cand
			break
		}
		dir = filepath.Dir(dir)
	}
	if prodPath == "" {
		t.Skip("config/allowlist.json not found (running outside repo root)")
	}

	a, err := Load(prodPath)
	if err != nil {
		t.Fatalf("load production allowlist %s: %v", prodPath, err)
	}

	// LOLBins the behavior rules target - MUST be untrusted, or those rules are
	// silently disabled for the incident's actors.
	lolbins := []string{
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Windows\System32\conhost.exe`,
		`C:\Windows\System32\schtasks.exe`,
		`C:\Windows\System32\mshta.exe`,
		`C:\Windows\System32\certutil.exe`,
		`C:\Windows\System32\wscript.exe`,
		`C:\Windows\System32\cscript.exe`,
		`C:\Windows\System32\rundll32.exe`,
		`C:\Windows\System32\regsvr32.exe`,
		`C:\Windows\System32\bitsadmin.exe`,
		`C:\Windows\System32\msiexec.exe`,
		`C:\Windows\System32\forfiles.exe`,
		`C:\Windows\System32\msdt.exe`,
	}
	for _, bin := range lolbins {
		if a.ImageTrusted(&event.Event{Image: bin}) {
			t.Errorf("LOLBin must NOT be trusted (would disable behavior rules): %s", bin)
		}
	}

	// Benign Windows binaries - MUST stay trusted so NET-002/003 don't toast-flood
	// from svchost/explorer phoning home. (If one of these is removed, expect NET
	// noise - verify that's intended.)
	benign := []string{
		`C:\Windows\explorer.exe`,
		`C:\Windows\System32\svchost.exe`,
		`C:\Windows\System32\lsass.exe`,
		`C:\Windows\System32\dwm.exe`,
	}
	for _, bin := range benign {
		if !a.ImageTrusted(&event.Event{Image: bin}) {
			t.Errorf("benign Windows binary should be trusted (removing it will add NET-002 noise): %s", bin)
		}
	}
}
