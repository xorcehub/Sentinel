package sysmonxml

import (
	"testing"

	"sentinel/internal/event"
)

// FuzzParse hunts panics and hangs in Parse on attacker-shaped input.
//
// Threat model: Sysmon generates the XML structure itself and guarantees
// well-formedness, but an attacker controls field VALUES (Image, CommandLine,
// Hashes, ...). A value-triggered panic in Parse runs at SYSTEM privilege and
// (without the Phase 1 per-event recover in sysmon_rt_windows.go) would crash
// the daemon = blind detection. This fuzzer finds the inputs that trigger a
// panic so we can fix the root cause, not just contain it.
//
// No correctness oracle: on garbage input, Parse may return a zero-value event
// with no error, and that's fine. The invariant is "never panic, never hang."
//
// Run on the host:
//
//	go test -fuzz=FuzzParse -fuzztime=5m ./internal/sysmonxml/
//
// Crashes are saved under testdata/fuzz/FuzzParse/ and become regression tests
// automatically on the next `go test` run.
func FuzzParse(f *testing.F) {
	// Seeds: the real fixtures from sysmonxml_test.go (EID 1/3/10, empty doc,
	// malformed non-XML) plus the empty byte slice. The fuzzer mutates these.
	f.Add([]byte(eid1XML))
	f.Add([]byte(eid3XML))
	f.Add([]byte(eid10XML))
	f.Add([]byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>7</EventID><EventRecordID>1</EventRecordID></System></Event>`))
	f.Add([]byte("not xml at all"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Discard return + error: we only assert Parse doesn't panic or hang.
		_, _ = Parse(data, event.SrcSysmonRT)
	})
}
