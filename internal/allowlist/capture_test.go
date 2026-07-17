package allowlist

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"sentinel/internal/event"
)

// ShouldCapture is the app layer's hook into the file_capture config: on an
// EID 11 (FileCreate) whose TargetFile matches a pattern, it returns the path
// to snapshot; otherwise "". These tests pin the contract that matters for the
// snapshot path: it fires ONLY on EID 11 + matching path, is nil-safe, and —
// critically — is decoupled from detection (it never looks at rules or excepts).

const captureAllowlistJSONC = `{
  "file_capture": {
    "patterns": [
      "\\\\temp\\\\ps-script-",
      "\\\\users\\\\[^\\\\]+\\\\appdata\\\\local\\\\temp\\\\dropper-"
    ]
  }
}`

func newCaptureAllowlist(t *testing.T) *Allowlist {
	t.Helper()
	a, err := Compile([]byte(captureAllowlistJSONC))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return a
}

func TestShouldCaptureMatchesCursorScript(t *testing.T) {
	a := newCaptureAllowlist(t)
	ev := &event.Event{
		EID:        11,
		TargetFile: `C:\Users\jurij\AppData\Local\Temp\ps-script-410dc456-e109-4a6e-864b-df8a8862b7ed.ps1`,
	}
	got := a.ShouldCapture(ev)
	if got != ev.TargetFile {
		t.Errorf("ShouldCapture should return the TargetFile for a matching ps-script; got %q", got)
	}
}

func TestShouldCaptureMatchesDropperPattern(t *testing.T) {
	a := newCaptureAllowlist(t)
	ev := &event.Event{
		EID:        11,
		TargetFile: `C:\Users\jurij\AppData\Local\Temp\dropper-stage2.exe`,
	}
	if got := a.ShouldCapture(ev); got != ev.TargetFile {
		t.Errorf("should match the dropper- pattern; got %q", got)
	}
}

func TestShouldCaptureRejectsNonMatchingPath(t *testing.T) {
	a := newCaptureAllowlist(t)
	for _, path := range []string{
		`C:\Windows\System32\cmd.exe`,
		`C:\Users\jurij\Documents\notes.txt`,
		`C:\Users\jurij\AppData\Local\Temp\other-file.txt`, // Temp but no ps-script-/dropper- prefix
	} {
		ev := &event.Event{EID: 11, TargetFile: path}
		if got := a.ShouldCapture(ev); got != "" {
			t.Errorf("ShouldCapture(%q) = %q; want \"\" (no pattern match)", path, got)
		}
	}
}

func TestShouldCaptureOnlyOnEID11and23(t *testing.T) {
	a := newCaptureAllowlist(t)
	// Same path that WOULD match on EID 11/23, but on other EIDs it must not —
	// capture is for FileCreate/FileDelete only. EID 1 (ProcessCreate)
	// TargetFile is always empty anyway.
	path := `C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef.ps1`
	for _, eid := range []int{1, 3, 13} {
		ev := &event.Event{EID: eid, TargetFile: path}
		if got := a.ShouldCapture(ev); got != "" {
			t.Errorf("ShouldCapture on EID %d should be \"\" (FileCreate/FileDelete only); got %q", eid, got)
		}
	}
	// And EID 11 + EID 23 with the same path DO match (FileCreate + FileDelete):
	if got := a.ShouldCapture(&event.Event{EID: 11, TargetFile: path}); got != path {
		t.Errorf("EID 11 with matching path should return the path; got %q", got)
	}
	if got := a.ShouldCapture(&event.Event{EID: 23, TargetFile: path}); got != path {
		t.Errorf("EID 23 with matching path should return the path; got %q", got)
	}
}

func TestShouldCaptureEmptyTargetFile(t *testing.T) {
	a := newCaptureAllowlist(t)
	if got := a.ShouldCapture(&event.Event{EID: 11, TargetFile: ""}); got != "" {
		t.Errorf("empty TargetFile should not capture; got %q", got)
	}
}

func TestShouldCaptureNilSafe(t *testing.T) {
	// A nil Allowlist (raw passthrough / no config) must never panic.
	var a *Allowlist
	if got := a.ShouldCapture(&event.Event{EID: 11, TargetFile: `C:\Temp\ps-script-x.ps1`}); got != "" {
		t.Errorf("nil Allowlist should return \"\"; got %q", got)
	}
	// A nil event is safe too.
	a = newCaptureAllowlist(t)
	if got := a.ShouldCapture(nil); got != "" {
		t.Errorf("nil event should return \"\"; got %q", got)
	}
}

func TestShouldCaptureNoPatternsConfigured(t *testing.T) {
	// An allowlist with no file_capture section must capture nothing — the
	// snapshot path stays a no-op until the operator opts in.
	a, err := Compile([]byte(`{ "trusted_binaries": { "path": [] } }`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	got := a.ShouldCapture(&event.Event{
		EID:        11,
		TargetFile: `C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef.ps1`,
	})
	if got != "" {
		t.Errorf("no patterns configured should not capture; got %q", got)
	}
}

func TestShouldCaptureForwardSlashPathNormalized(t *testing.T) {
	// Sysmon normally reports backslash paths, but the normalizer unifies
	// forward slashes too (git-bash /x/ form). A ps-script created via a
	// forward-slash path should still match.
	a := newCaptureAllowlist(t)
	ev := &event.Event{
		EID:        11,
		TargetFile: `C:/Users/jurij/AppData/Local/Temp/ps-script-norm.ps1`,
	}
	if got := a.ShouldCapture(ev); got != ev.TargetFile {
		t.Errorf("forward-slash path should match after normalization; got %q", got)
	}
}

// TestShouldCaptureRealShippedConfig loads the REAL config/allowlist.json and
// asserts the shipped Cursor pattern actually matches a realistic event. This
// fails if someone edits the pattern into something that no longer catches
// ps-script files (the whole point of the feature).
func TestShouldCaptureRealShippedConfig(t *testing.T) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "config", "allowlist.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("allowlist.json not present (%v); skipping real-config test", err)
	}
	a, err := Load(path)
	if err != nil {
		t.Fatalf("Load real allowlist: %v", err)
	}
	if len(a.capPatterns) == 0 {
		t.Fatal("shipped allowlist has no file_capture patterns; the Cursor snapshot feature is unarmed")
	}
	ev := &event.Event{
		EID:        11,
		TargetFile: `C:\Users\jurij\AppData\Local\Temp\ps-script-410dc456-e109-4a6e-864b-df8a8862b7ed.ps1`,
	}
	if got := a.ShouldCapture(ev); got != ev.TargetFile {
		t.Errorf("shipped config should match a cursor ps-script path; got %q\npatterns: %s",
			got, strings.Join(rawPatterns(a), ", "))
	}
}

// rawPatterns dumps the compiled patterns for test diagnostics.
func rawPatterns(a *Allowlist) []string {
	out := make([]string, len(a.capPatterns))
	for i, re := range a.capPatterns {
		out[i] = re.String()
	}
	return out
}

func TestShouldCaptureEID23(t *testing.T) {
	re := regexp.MustCompile(`\\temp\\ps-script-`)
	a := &Allowlist{capPatterns: []*regexp.Regexp{re}}
	ev := &event.Event{
		EID:        23,
		TargetFile: `C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef.ps1`,
	}
	got := a.ShouldCapture(ev)
	if got == "" {
		t.Error("ShouldCapture should match EID 23 (FileDelete) for ps-script pattern")
	}
	if got != ev.TargetFile {
		t.Errorf("ShouldCapture should return TargetFile; got %q", got)
	}
}
