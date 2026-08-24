//go:build windows

package ingest

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"gopkg.in/yaml.v3"
)

// H3 invariant (docs/hardening-plan_2308.md): every EventID referenced by a
// rule in rules.d/ must be subscribed to by defaultEIDs — otherwise the poller
// never fetches it and the rule silently never fires (the INJECT-002/CRED-002
// bug family: right rule, wrong/unseen field).
//
// sigmaeval.Rule compiles selections into opaque closures and does NOT retain
// raw EventID fields, so this test parses rules.d/*.yml directly with yaml.v3.
// selectionShape tolerates scalar OR list EventID values.
type selectionShape struct {
	EventID any `yaml:"EventID"`
}

func TestDefaultEIDsCoverAllRuleEventIDs(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Join(filepath.Dir(file), "..", "..", "rules.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("rules.d not present (%v); skipping EID-coverage invariant", err)
	}

	for _, e := range entries {
		if e.IsDir() || (filepath.Ext(e.Name()) != ".yml" && filepath.Ext(e.Name()) != ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		for doc := 1; ; doc++ {
			// Named Condition field keeps yaml.v3 from inline-decoding the
			// `condition: selection` string into the selection map (which fails
			// every document and made an earlier revision of this test vacuously
			// pass with zero selections walked).
			var d struct {
				Title     string `yaml:"title"`
				Detection struct {
					Condition  string                    `yaml:"condition"`
					Selections map[string]selectionShape `yaml:",inline"`
				} `yaml:"detection"`
			}
			err := dec.Decode(&d)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Errorf("%s doc %d: YAML decode failed (rule skipped from EID check): %v", e.Name(), doc, err)
				}
				break // EOF: next file
			}
			for selName, sel := range d.Detection.Selections {
				if sel.EventID == nil {
					continue // no EventID in this selection → wildcard, skip
				}
				for _, id := range eventIDs(sel.EventID) {
					if !intIn(defaultEIDs, id) {
						t.Errorf("%s: %q selection %q uses EventID %d, which defaultEIDs does NOT subscribe to — the rule can never fire",
							e.Name(), d.Title, selName, id)
					}
				}
			}
		}
	}
}

// eventIDs normalizes a selection's EventID value (scalar int or list) to ints.
func eventIDs(v any) []int {
	switch x := v.(type) {
	case int:
		return []int{x}
	case float64: // defensive: yaml.v3 decodes untyped scalars as int, but be safe
		return []int{int(x)}
	case string:
		if n, err := strconv.Atoi(x); err == nil {
			return []int{n}
		}
	case []any:
		var out []int
		for _, item := range x {
			out = append(out, eventIDs(item)...)
		}
		return out
	}
	return nil
}

func intIn(ids []int, want int) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
