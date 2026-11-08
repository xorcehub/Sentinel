package sigmaeval

import (
	"strings"
	"testing"

	"sentinel/internal/event"
)

const overlayBaseRule = `
title: base
logsource: { product: windows }
detection:
  selection:
    Image|endswith: '\powershell.exe'
  filter_x:
    CommandLine|contains: 'shipped-filter'
  condition: selection and not filter_x
x-sentinel:
  id: T-001
  severity: critical
`

func loadOne(t *testing.T, yaml string) *Rule {
	t.Helper()
	rs, err := Load([]byte(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, r := range rs {
		if r.XID == "T-001" {
			return r
		}
	}
	t.Fatalf("T-001 not loaded")
	return nil
}

func TestOverlaySuppressesOnlyItsShape(t *testing.T) {
	r := loadOne(t, overlayBaseRule+`---
title: quiet the dev tool
x-sentinel-overlay:
  rule: T-001
detection:
  filter_x:
    CommandLine|contains: 'devtool'
  condition: filter_x
`)
	if r.OverlayCount() != 1 {
		t.Fatalf("OverlayCount = %d, want 1", r.OverlayCount())
	}
	ps := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	cases := []struct {
		cmd  string
		want bool
	}{
		{"powershell -c devtool", false},        // overlay suppresses
		{"powershell -c evil", true},            // still armed
		{"powershell -c shipped-filter", false}, // base filter unaffected
	}
	for _, c := range cases {
		if got := r.Match(&event.Event{Image: ps, CmdLine: c.cmd}); got != c.want {
			t.Errorf("%q: Match = %v, want %v", c.cmd, got, c.want)
		}
	}
	// An overlay can never make a non-matching event match.
	if r.Match(&event.Event{Image: `C:\x\cmd.exe`, CmdLine: "devtool"}) {
		t.Error("overlay widened the rule")
	}
}

// Overlay selection names are local: an overlay reusing a base selection's
// name (filter_x above) does not change the base rule's own filter_x.
func TestOverlaySelectionNamesDoNotLeakIntoBase(t *testing.T) {
	r := loadOne(t, overlayBaseRule+`---
title: same name, different meaning
x-sentinel-overlay:
  rule: T-001
detection:
  filter_x:
    CommandLine|contains: 'nothing-real-matches-this'
  condition: filter_x
`)
	ps := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	if r.Match(&event.Event{Image: ps, CmdLine: "shipped-filter"}) {
		t.Error("base filter_x stopped working after an overlay reused the name")
	}
}

func TestOverlayLoadErrors(t *testing.T) {
	bad := []struct{ name, doc, want string }{
		{"unknown target", `title: o
x-sentinel-overlay: { rule: NOPE-9 }
detection: { f: { Image: x }, condition: f }`, "not loaded"},
		{"rule-level key smuggled in", `title: o
x-sentinel-overlay: { rule: T-001 }
x-sentinel: { severity: info }
detection: { f: { Image: x }, condition: f }`, "not allowed"},
		{"extra header key", `title: o
x-sentinel-overlay: { rule: T-001, mode: replace }
detection: { f: { Image: x }, condition: f }`, "unknown key"},
		{"missing rule", `title: o
x-sentinel-overlay: {}
detection: { f: { Image: x }, condition: f }`, "must name"},
		{"missing condition", `title: o
x-sentinel-overlay: { rule: T-001 }
detection: { f: { Image: x } }`, "missing condition"},
	}
	for _, b := range bad {
		_, err := Load([]byte(overlayBaseRule + "---\n" + b.doc + "\n"))
		if err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%s: err = %v, want containing %q", b.name, err, b.want)
		}
	}
}

// Overlays may come before the rule they target (directory order does not
// matter): they are attached after every rule is compiled.
func TestOverlayOrderIndependent(t *testing.T) {
	rs, err := Load([]byte(`title: early
x-sentinel-overlay: { rule: T-001 }
detection: { f: { CommandLine|contains: devtool }, condition: f }
---
` + overlayBaseRule))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rs) != 1 || rs[0].OverlayCount() != 1 {
		t.Fatalf("got %d rules / overlays %d, want 1 rule with 1 overlay", len(rs), rs[0].OverlayCount())
	}
}
