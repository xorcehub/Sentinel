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
