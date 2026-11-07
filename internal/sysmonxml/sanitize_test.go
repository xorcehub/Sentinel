package sysmonxml

import (
	"bytes"
	"strings"
	"testing"

	"sentinel/internal/event"
)

func eid1WithCmd(cmd string) []byte {
	return []byte(`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>` +
		`<System><EventID>1</EventID><EventRecordID>5</EventRecordID></System><EventData>` +
		`<Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>` +
		`<Data Name='CommandLine'>` + cmd + `</Data></EventData></Event>`)
}

// Regression (2026-11-07 review): one XML-illegal character anywhere in an
// attacker-controlled field made encoding/xml reject the whole document, so
// the event was dropped before rule evaluation — a one-byte detection bypass.
// Every variant must now parse, keep the rest of the command line intact, and
// mark the bad character with U+FFFD.
func TestParseSurvivesXMLIllegalCharacters(t *testing.T) {
	const base = "powershell -ep bypass -c iex x"
	cases := map[string]string{
		"raw U+0001":       base + "\x01",
		"raw U+001F mid":   "powershell -ep bypass\x1f -c iex x",
		"ref hex &#x1;":    base + "&#x1;",
		"ref dec &#1;":     base + "&#1;",
		"ref &#xFFFF;":     base + "&#xFFFF;",
		"ref &#xFFFE;":     base + "&#xFFFE;",
		"ref out of range": base + "&#x110000;",
		"ref zero":         base + "&#0;",
		"invalid utf8":     base + "\xff\xfe",
		"raw U+FFFF":       base + "\uffff",
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			ev, err := Parse(eid1WithCmd(cmd), event.SrcSysmonRT)
			if err != nil {
				t.Fatalf("Parse rejected event: %v", err)
			}
			if ev.EID != 1 || ev.RecordID != 5 {
				t.Fatalf("event header lost: eid=%d rec=%d", ev.EID, ev.RecordID)
			}
			if !strings.Contains(ev.CmdLine, "-ep bypass") || !strings.Contains(ev.CmdLine, "iex x") {
				t.Fatalf("command line content lost: %q", ev.CmdLine)
			}
			if !strings.ContainsRune(ev.CmdLine, '\uFFFD') {
				t.Fatalf("illegal character not marked with U+FFFD: %q", ev.CmdLine)
			}
		})
	}
}

// Legal input must pass through byte-identical (no allocation, same slice),
// including valid character and entity references.
func TestSanitizeXMLLeavesValidInputAlone(t *testing.T) {
	for _, s := range []string{
		string(eid1WithCmd("plain cmd")),
		string(eid1WithCmd("tab\there &amp; &lt;x&gt; &#x41; &#65; \u00e9 \u2013 \U0001F600")),
	} {
		in := []byte(s)
		out := SanitizeXML(in)
		if !bytes.Equal(in, out) {
			t.Fatalf("valid input changed:\n in=%q\nout=%q", in, out)
		}
	}
	ev, err := Parse(eid1WithCmd("a &#x41;&#66; b"), event.SrcSysmonRT)
	if err != nil || ev.CmdLine != "a AB b" {
		t.Fatalf("valid char refs mangled: %q err=%v", ev.CmdLine, err)
	}
}

// Malformed-but-not-character problems are still errors (sanitizing must not
// turn garbage into an accepted event).
func TestSanitizeXMLKeepsStructuralErrors(t *testing.T) {
	if _, err := Parse([]byte("<Event><System>"), event.SrcSysmonRT); err == nil {
		t.Fatal("truncated XML accepted")
	}
	// A bare "&#" with no terminator is left for encoding/xml to reject.
	if _, err := Parse(eid1WithCmd("x &#zz y"), event.SrcSysmonRT); err == nil {
		t.Fatal("malformed reference accepted")
	}
}
