package selftest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// findRulesDir locates the repo-root rules.d/ from the test working directory
// (package dir). Walks up until found.
func findRulesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "rules.d")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find rules.d/ walking up from " + filepath.Dir(file))
	return ""
}

// loadCatalog concatenates every .yml in dir, inserting a YAML document
// separator (---) between files so the concatenated blob is a valid
// multi-doc stream. Mirrors main.loadRulesDir.
func loadCatalog(t *testing.T, dir string) []byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []byte
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
		out = append(out, b...)
		if len(b) > 0 && b[len(b)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, "---\n"...)
	}
	return out
}

// TestIncidentCoverageAgainstCatalog is the Phase-2 regression gate: load the
// real rules.d/ catalog and confirm every ⭐ incident vector fires the expected
// rules, and benign inputs do not. Run after every rule/engine change.
func TestIncidentCoverageAgainstCatalog(t *testing.T) {
	dir := findRulesDir(t)
	catalog := loadCatalog(t, dir)
	if len(catalog) == 0 {
		t.Fatal("catalog is empty — no .yml files in rules.d/")
	}

	results, allPassed, err := Run(catalog)
	if err != nil {
		t.Fatalf("selftest.Run: %v", err)
	}
	if !allPassed {
		t.Errorf("self-test FAILED — coverage regression detected")
	}
	for _, r := range results {
		t.Run(r.Case.Name, func(t *testing.T) {
			if !r.Passed {
				t.Errorf("\n  fired:  %v\n  %s", r.Fired, r.Detail)
			} else if len(r.Fired) > 0 {
				t.Logf("fired: %s", strings.Join(r.Fired, ", "))
			}
		})
	}
}
