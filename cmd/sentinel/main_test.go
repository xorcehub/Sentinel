package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveExeRelativePassthrough: an already-absolute path must pass through
// unchanged (CLI overrides like `-log C:\logs\s.log` are respected).
func TestResolveExeRelativePassthrough(t *testing.T) {
	fl := flags{logPath: `C:\logs\s.log`, rulesDir: `D:\rules`}
	resolveExeRelative(&fl)
	if fl.logPath != `C:\logs\s.log` {
		t.Errorf("absolute path rewritten: got %q", fl.logPath)
	}
	if fl.rulesDir != `D:\rules` {
		t.Errorf("absolute path rewritten: got %q", fl.rulesDir)
	}
}

// TestResolveExeRelativeMakesAbsolute: a relative default must become absolute,
// joined to the exe's directory. (This is the Task-Scheduler fix: without it,
// rules.d resolves against system32 and the engine silently degrades to
// passthrough.) We only assert the result is absolute and has the original path
// as a suffix — the exe's actual dir depends on where the test binary runs.
func TestResolveExeRelativeMakesAbsolute(t *testing.T) {
	fl := flags{rulesDir: "rules.d", statePath: "state.db"}
	resolveExeRelative(&fl)

	if !filepath.IsAbs(fl.rulesDir) {
		t.Errorf("rulesDir not made absolute: got %q", fl.rulesDir)
	}
	if !filepath.IsAbs(fl.statePath) {
		t.Errorf("statePath not made absolute: got %q", fl.statePath)
	}
	// The relative tail must be preserved (joined under the exe dir).
	if filepath.Base(fl.rulesDir) != "rules.d" {
		t.Errorf("rulesDir tail lost: got %q", fl.rulesDir)
	}
}

// TestWriteReportWritesFileNextToExe pins the one-shot output contract: every
// one-shot command (self-test / baseline-snapshot / baseline-now) routes its
// report through writeReport so the result survives the windowsgui build's dead
// stdout handle. The file must land next to the exe, contain the text verbatim,
// and be named <name>.txt. (stdout itself can't be asserted in-test, but the
// file is the mandatory channel — that's what this pins.)
func TestWriteReportWritesFileNextToExe(t *testing.T) {
	text := "line one\nline two\n"
	path, err := writeReport("sentinel-test-report", text)
	if err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	if filepath.Base(path) != "sentinel-test-report.txt" {
		t.Errorf("report filename = %q, want sentinel-test-report.txt", filepath.Base(path))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if string(got) != text {
		t.Errorf("report content mismatch:\ngot  %q\nwant %q", string(got), text)
	}
	if !strings.HasSuffix(path, "sentinel-test-report.txt") {
		t.Errorf("path = %q", path)
	}
}

// The per-box allowlist is picked up by presence, like rules.d/local/.
func TestPreferLocalAllowlist(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "allowlist.json")
	if err := os.WriteFile(def, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Fresh clone: no .local file -> the default stays.
	fl := flags{allowlistPath: def}
	preferLocalAllowlist(&fl, false)
	if fl.allowlistPath != def {
		t.Fatalf("no .local present: path changed to %q", fl.allowlistPath)
	}

	local := def + ".local"
	if err := os.WriteFile(local, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Tuned box, no flag: the .local file wins.
	fl = flags{allowlistPath: def}
	preferLocalAllowlist(&fl, false)
	if fl.allowlistPath != local {
		t.Fatalf(".local present, no flag: got %q, want %q", fl.allowlistPath, local)
	}
	// Explicit -allowlist always wins, even when .local exists.
	fl = flags{allowlistPath: def}
	preferLocalAllowlist(&fl, true)
	if fl.allowlistPath != def {
		t.Fatalf("explicit -allowlist overridden: got %q", fl.allowlistPath)
	}
}

func TestFlagSetDetectsExplicitAllowlist(t *testing.T) {
	_, fs := parseFlags(nil)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}
	if flagSet(fs, "allowlist") {
		t.Error("no args: allowlist reported as set")
	}
	_, fs = parseFlags(nil)
	if err := fs.Parse([]string{"-allowlist", `C:\x\a.json`}); err != nil {
		t.Fatal(err)
	}
	if !flagSet(fs, "allowlist") {
		t.Error("-allowlist given: not reported as set")
	}
}
