package rules

import (
	"testing"

	"sentinel/internal/event"
	"sentinel/internal/sysmonxml"
)

// End-to-end regression (2026-11-07 review): an XML-illegal character in the
// command line (raw U+0001 or the reference &#x1;) made sysmonxml.Parse reject
// the whole event, so EXEC-001 never saw a -ExecutionPolicy Bypass launch that
// carried one. Parse now replaces the character with U+FFFD; the launch must
// reach the real catalog and fire.
func TestControlCharCmdLineStillFiresEXEC001(t *testing.T) {
	const cmd = `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef.ps1`
	for name, tail := range map[string]string{"raw": "\x01", "ref": "&#x1;", "ref zero-padded": "&#00000000001;"} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>` +
				`<System><EventID>1</EventID><EventRecordID>77</EventRecordID></System><EventData>` +
				`<Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>` +
				`<Data Name='CommandLine'>` + cmd + ` ` + tail + `</Data></EventData></Event>`)
			ev, err := sysmonxml.Parse(raw, event.SrcSysmonRT)
			if err != nil {
				t.Fatalf("event dropped at parse: %v", err)
			}
			res := realEngine(t).Evaluate(&ev)
			if !containsRule(hitRuleIDs(res), "EXEC-001") {
				t.Fatalf("EXEC-001 must fire; hits=%v suppressed=%v", hitRuleIDs(res), suppRuleIDs(res))
			}
		})
	}
}

// Vertical tab / form feed between the switch and its value: whitespace to
// PowerShell's tokenizer, so the token form must still be seen. Before the
// space fold these became U+FFFD ("-ExecutionPolicy\uFFFDBypass") and the
// space-separated token rules missed.
func TestVTabFormFeedSeparatorStillFiresEXEC001(t *testing.T) {
	for name, sep := range map[string]string{"raw VT": "\v", "raw FF": "\f", "ref VT": "&#xb;", "ref FF": "&#12;"} {
		t.Run(name, func(t *testing.T) {
			cmd := `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy` + sep +
				`Bypass -NonInteractive -File C:\Users\jurij\AppData\Local\Temp\ps-script-deadbeef.ps1`
			raw := []byte(`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>` +
				`<System><EventID>1</EventID><EventRecordID>78</EventRecordID></System><EventData>` +
				`<Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>` +
				`<Data Name='CommandLine'>` + cmd + `</Data></EventData></Event>`)
			ev, err := sysmonxml.Parse(raw, event.SrcSysmonRT)
			if err != nil {
				t.Fatalf("event dropped at parse: %v", err)
			}
			res := realEngine(t).Evaluate(&ev)
			if !containsRule(hitRuleIDs(res), "EXEC-001") {
				t.Fatalf("EXEC-001 must fire; cmd=%q hits=%v suppressed=%v", ev.CmdLine, hitRuleIDs(res), suppRuleIDs(res))
			}
		})
	}
}
