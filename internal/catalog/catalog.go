// Package catalog reads the rule catalog from disk: the shipped rules in a
// rules directory plus optional overlay directories.
//
// Layout (all under the rules directory, default rules.d/):
//
//	rules.d/*.yml               shipped catalog, tracked, NO per-box tuning
//	rules.d/local/*.yml         this box's overlays (gitignored, optional)
//	rules.d/local.example/*.yml worked example of overlays (tracked, never loaded
//	                            by the daemon; tests load it as the "tuned box")
//
// Same split as config/allowlist.json (empty default) / .json.example /
// .json.local: a fresh clone runs every rule fully armed, and per-box tuning
// is something the operator opts into by creating rules.d/local/. Overlay
// semantics (suppress-only, one target rule each) live in sigmaeval.Load.
// Keeping overlays under rules.d\ also keeps them inside the CONFIG-001
// tamper rule and the Sysmon FileCreate include, both of which key on the
// `\rules.d\` path substring.
package catalog

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// LocalDir is the per-box overlay directory inside the rules directory.
	LocalDir = "local"
	// ExampleDir holds the tracked worked-example overlays.
	ExampleDir = "local.example"
)

// Read concatenates every *.yml/*.yaml file directly in dir, then every such
// file in each overlay dir, into one multi-document YAML stream ready for
// sigmaeval.Load. Files are read in name order within each directory.
// Overlay dirs that do not exist are skipped; dir itself must exist and hold
// at least one rule file.
func Read(dir string, overlayDirs ...string) (data []byte, overlayFiles int, err error) {
	n, err := appendDir(&data, dir)
	if err != nil {
		return nil, 0, err
	}
	if n == 0 {
		return nil, 0, fmt.Errorf("no .yml rule files in %s", dir)
	}
	for _, od := range overlayDirs {
		if fi, statErr := os.Stat(od); statErr != nil || !fi.IsDir() {
			continue
		}
		k, err := appendDir(&data, od)
		if err != nil {
			return nil, 0, err
		}
		overlayFiles += k
	}
	return data, overlayFiles, nil
}

// ReadLive is what the daemon loads: dir plus dir/local.
func ReadLive(dir string) ([]byte, int, error) {
	return Read(dir, filepath.Join(dir, LocalDir))
}

func appendDir(out *[]byte, dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
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
			return n, err
		}
		*out = append(*out, b...)
		// Newline + document separator between files: without it the last
		// document of one file and the first of the next merge into a single
		// mapping with duplicate keys.
		if len(b) > 0 && b[len(b)-1] != '\n' {
			*out = append(*out, '\n')
		}
		*out = append(*out, "---\n"...)
		n++
	}
	return n, nil
}
