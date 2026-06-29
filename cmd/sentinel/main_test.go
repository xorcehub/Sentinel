package main

import (
	"path/filepath"
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
