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

// TestDstIsKnownLoopbackCanonicalizesIPv6 pins the 2026-09-01 fix: Sysmon
// delivers IPv6 loopback in EXPANDED form (0:0:0:0:0:0:0:1), so an entry
// spelled "::1:9080" must still match an event carrying the expanded form
// (and vice versa). Before the fix the comparison was a raw string key and
// both spellings silently missed each other.
func TestDstIsKnownLoopbackCanonicalizesIPv6(t *testing.T) {
	a, err := Compile([]byte(`{
  "known_loopback_listeners": ["::1:9080", "127.0.0.1:9080"]
}`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cases := []struct {
		ip   string
		port int
		want bool
	}{
		{"0:0:0:0:0:0:0:1", 9080, true},  // expanded form vs ::1 entry
		{"::1", 9080, true},              // canonical vs canonical
		{"127.0.0.1", 9080, true},        // v4 exact
		{"0:0:0:0:0:0:0:1", 9081, false}, // wrong port
		{"127.0.0.2", 9080, false},       // wrong ip
	}
	for _, c := range cases {
		if got := a.DstIsKnownLoopback(c.ip, c.port); got != c.want {
			t.Errorf("DstIsKnownLoopback(%q,%d)=%v want %v", c.ip, c.port, got, c.want)
		}
	}
}

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

// TestCmdLineInDevScripts pins the commandline-anchored exception used by
// EXEC-001's `cmdline_in_dev_scripts`. Unlike the image-based sets, this matches
// the CommandLine so a developer's own `powershell -ep bypass -File <dev.ps1>`
// workflow can be suppressed WITHOUT trusting powershell.exe (which would blind
// EXEC-001 to every PS-bypass attack). Must match both absolute and relative
// -File invocations of the trusted script, and must NOT match a hostile script
// of a different name.
func TestCmdLineInDevScripts(t *testing.T) {
	a, err := Compile([]byte(`{
  "dev_scripts": [
    "pe-triage-docker\\.ps1"
  ]
}`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	abs := `powershell -ExecutionPolicy Bypass -File C:\Users\user01\Documents\Github\pe_triage\scripts\pe-triage-docker.ps1 arg`
	rel := `powershell -ExecutionPolicy Bypass -File ./scripts/pe-triage-docker.ps1`
	if !a.CmdLineInDevScripts(abs) {
		t.Error("absolute -File invocation of dev script must match")
	}
	if !a.CmdLineInDevScripts(rel) {
		t.Error("relative -File invocation of dev script must match")
	}
	// Hostile script of a different name must NOT match (EXEC-001 stays armed).
	if a.CmdLineInDevScripts(`powershell -ep bypass -File C:\ProgramData\evil.ps1`) {
		t.Error("unrelated hostile script must NOT match dev_scripts")
	}
	// Empty cmdline + nil allowlist must be safe (no panic).
	if a.CmdLineInDevScripts("") {
		t.Error("empty cmdline should not match")
	}
	var nilAL *Allowlist
	if nilAL.CmdLineInDevScripts(abs) {
		t.Error("nil allowlist must be safe and not match")
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

// TestProductionAllowlistDevTuning pins the operator's FP-tuning entries against
// the REAL config/allowlist.json: pi-lite in dev_tool_paths (quiets NET-002/003
// for the operator's dev AI agent) and pe-triage-docker.ps1 in dev_scripts
// (quiets EXEC-001 for the operator's own PS-bypass dev workflow). These are
// the two known false positives surfaced during on-host use. If the entries are
// accidentally removed/renamed, this test surfaces the regression immediately.
//
// Importantly it also asserts the tuning is SCOPED: pi-lite's entry does not
// trust unrelated dev tools, and dev_scripts does not suppress EXEC-001 for a
// hostile ProgramData script (EXEC-001 must stay armed).
func TestProductionAllowlistDevTuning(t *testing.T) {
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
		t.Fatalf("load production allowlist: %v", err)
	}

	// pi-lite (NET-002/003 FP): the built binary must be a trusted dev tool,
	// and the scoping must not over-match a sibling dev tool.
	if !a.ImageInDevTools(`C:\Users\user01\Documents\Github\pi-lite\dist\pi-lite.exe`) {
		t.Error("pi-lite built binary should be in dev_tool_paths (NET-002/003 FP tuning)")
	}
	if a.ImageInDevTools(`C:\Users\user01\Documents\Github\other-tool\dist\tool.exe`) {
		t.Error("pi-lite dev_tool_paths entry over-matches an unrelated tool")
	}

	// pe-triage-docker.ps1 (EXEC-001 FP): both invocation forms match dev_scripts,
	// but a hostile ProgramData script must NOT (EXEC-001 stays armed).
	abs := `powershell -ExecutionPolicy Bypass -File C:\Users\user01\Documents\Github\pe_triage\scripts\pe-triage-docker.ps1`
	rel := `powershell -ExecutionPolicy Bypass -File ./scripts/pe-triage-docker.ps1`
	if !a.CmdLineInDevScripts(abs) || !a.CmdLineInDevScripts(rel) {
		t.Error("pe-triage-docker.ps1 (both abs + rel -File forms) should be in dev_scripts (EXEC-001 FP tuning)")
	}
	if a.CmdLineInDevScripts(`powershell -ep bypass -File C:\ProgramData\evil.ps1`) {
		t.Error("dev_scripts must NOT match a hostile ProgramData script (EXEC-001 would be blinded)")
	}
}

// TestProductionAllowlistDriveRootAnchored is the regression for the unanchored-
// regex bypass: every trusted_binaries / dev_tool_paths path pattern is matched
// via regexp.MatchString (UNANCHORED) on the normalized lower path, so without
// a leading anchor a binary dropped anywhere the path merely CONTAINS a trusted
// substring was treated as trusted — suppressing every rule keyed on
// image_in_allowlist / image_in_dev_tools. Verified-exploitable examples before
// the fix: C:\Users\Public\Program Files\Mozilla Firefox\implant.exe,
// C:\Windows\Temp\Program Files\7-Zip\evil.exe, and a planted
// C:\Users\Public\Windows\System32\svchost.exe (fake system32 sibling).
//
// The fix prepends ^[a-z]: to each path pattern: NormalizePath always emits
// "<drive-letter>:\...", so the anchor pins the match to the drive root and the
// trusted substring can no longer appear mid-path in a user-writable location.
// This test loads the REAL config/allowlist.json and asserts both halves:
// cross-directory substring mimics must be UNtrusted, while legit install paths
// (including a non-C drive, proving the anchor is [a-z]: and not literal c:)
// stay trusted.
//
// KNOWN LIMITATION (not asserted here, by design): this anchor does NOT close
// per-user-profile mimicry — patterns like ^[a-z]:\users\[^\\]+\appdata\local\
// programs\cursor\.*\exe$ intentionally wildcard the username, so malware running
// AS the user can drop into C:\Users\<thatuser>\AppData\Local\Programs\Cursor\
// and still match. Closing that requires trusting the sha256 set (currently
// empty) rather than path patterns. The drive-root anchor removes the
// cross-directory class only.
func TestProductionAllowlistDriveRootAnchored(t *testing.T) {
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
		t.Fatalf("load production allowlist: %v", err)
	}

	// Attacker paths: a trusted substring planted in a user-writable / wrong
	// location. Before the drive-root anchor these all returned trusted=true and
	// silently disabled every image_in_allowlist / image_in_dev_tools rule.
	attacks := []struct {
		name  string
		image string
	}{
		{"firefox substring under Public", `C:\Users\Public\Program Files\Mozilla Firefox\implant.exe`},
		{"7-zip substring under Windows Temp", `C:\Windows\Temp\Program Files\7-Zip\evil.exe`},
		{"fake system32 sibling dir", `C:\Users\Public\Windows\System32\svchost.exe`},
		{"programdata defender substring mimic", `C:\Users\Public\ProgramData\Microsoft\Windows Defender\MpCmdRun.exe`},
		{"go bin substring under Temp", `C:\Users\user01\AppData\Local\Temp\Program Files\Git\bin\git.exe`},
	}
	for _, c := range attacks {
		t.Run("attack/"+c.name, func(t *testing.T) {
			if a.ImageTrusted(&event.Event{Image: c.image}) {
				t.Errorf("attacker path must NOT be trusted (unanchored-regex bypass): %s", c.image)
			}
			if a.ImageInDevTools(c.image) {
				t.Errorf("attacker path must NOT be a dev tool (same unanchored class): %s", c.image)
			}
		})
	}

	// Legit install paths: must stay trusted. Includes a D: drive to prove the
	// anchor is [a-z]: (any drive), not a literal c: that would break multi-drive
	// boxes. Per-user patterns wildcard the username, so a real Cursor install
	// for an arbitrary user must still match.
	legit := []struct {
		name  string
		image string
	}{
		{"firefox (C:)", `C:\Program Files\Mozilla Firefox\firefox.exe`},
		{"7-zip (D: drive)", `D:\Program Files\7-Zip\7z.exe`},
		{"firefox (D: drive)", `D:\Program Files\Mozilla Firefox\firefox.exe`},
		{"real system32 svchost", `C:\Windows\System32\svchost.exe`},
		{"per-user cursor install", `C:\Users\anyone\AppData\Local\Programs\Cursor\Cursor.exe`},
		{"per-user go bin", `C:\Users\anyone\go\bin\task.exe`},
	}
	for _, c := range legit {
		t.Run("legit/"+c.name, func(t *testing.T) {
			// Some legit cases are trusted_binaries, some dev_tool_paths; assert via
			// the union so a path that legitimately lives in only one set still passes.
			trusted := a.ImageTrusted(&event.Event{Image: c.image}) || a.ImageInDevTools(c.image)
			if !trusted {
				t.Errorf("legit path should be trusted or a dev tool (anchor too strict?): %s", c.image)
			}
		})
	}
}
