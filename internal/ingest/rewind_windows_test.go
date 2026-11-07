//go:build windows

package ingest

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf16"

	"sentinel/internal/event"
)

// Log-clear recovery (2026-11-07 review): after `wevtutil cl` RecordIds restart
// at 1 and the old monotonic high-water filtered every new event forever.
func TestRecordIDsRewound(t *testing.T) {
	cases := []struct {
		chanMax, highWater int64
		want               bool
	}{
		{12, 884213, true},      // log cleared, new records below the high-water
		{884213, 884213, false}, // nothing new
		{884300, 884213, false}, // normal progress
		{-1, 884213, false},     // channel returned nothing: unknown, not a rewind
		{5, -1, false},          // first poll after start: nothing consumed yet
		{0, 1, true},            // degenerate but still backwards
	}
	for _, c := range cases {
		if got := recordIDsRewound(c.chanMax, c.highWater); got != c.want {
			t.Errorf("recordIDsRewound(%d, %d) = %v, want %v", c.chanMax, c.highWater, got, c.want)
		}
	}
}

func TestParseChanMax(t *testing.T) {
	if id, ok := parseChanMax(chanMaxPrefix + "884213"); !ok || id != 884213 {
		t.Fatalf("marker not parsed: id=%d ok=%v", id, ok)
	}
	for _, bad := range []string{"", "884213", chanMaxPrefix, chanMaxPrefix + "x", chanMaxPrefix + "-3"} {
		if _, ok := parseChanMax(bad); ok {
			t.Errorf("parseChanMax(%q) accepted", bad)
		}
	}
	// An event line is base64, which has no ':' — it can never look like the marker.
	line := base64.StdEncoding.EncodeToString([]byte("CHANMAX:1 as event payload"))
	if _, ok := parseChanMax(line); ok {
		t.Fatalf("base64 event line mistaken for the marker: %q", line)
	}
}

// The synthetic event must carry exactly what TELEMETRY-002 selects on
// (Source=sentinel, Details prefix); internal/rules pins the rule side.
func TestRewoundEventShape(t *testing.T) {
	ev := rewoundEvent("Microsoft-Windows-Sysmon/Operational", 12, 884213)
	if ev.Source != event.SrcSentinel || ev.EID != 0 || ev.RecordID != 0 {
		t.Fatalf("wrong envelope: %+v", ev)
	}
	if !strings.HasPrefix(ev.Details, event.DetailsSysmonRewound) ||
		!strings.Contains(ev.Details, "newest_record_id=12") ||
		!strings.Contains(ev.Details, "previous_high_water=884213") {
		t.Fatalf("details missing rewind facts: %q", ev.Details)
	}
}

// Undecodable lines must be counted and logged, not skipped silently.
func TestNoteDroppedLogsAndCounts(t *testing.T) {
	var buf bytes.Buffer
	s := &sysmonRT{log: slog.New(slog.NewTextHandler(&buf, nil))}
	s.noteDropped(errTest("first"))
	s.noteDropped(errTest("second")) // inside the rate-limit window: counted, not logged
	if s.dropped != 2 {
		t.Fatalf("dropped=%d, want 2", s.dropped)
	}
	out := buf.String()
	if strings.Count(out, "sysmon event dropped") != 1 || !strings.Contains(out, "first") {
		t.Fatalf("want exactly one WARN for the first drop, got:\n%s", out)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

// A record whose ToXml() throws in PowerShell must come back as a marker line
// (counted as a drop in Go), not vanish in an empty catch block. The catch
// must read the RECORD's id: inside catch, $_ is the ErrorRecord.
func TestPollScriptReportsToXMLFailures(t *testing.T) {
	s := &sysmonRT{channel: "Microsoft-Windows-Sysmon/Operational", eids: defaultEIDs, maxPerPoll: 2000}
	script := s.pollScript(42, false)
	if !strings.Contains(script, `catch { '`+toXMLFailPrefix+`' + $r.RecordId }`) {
		t.Fatalf("ToXml failures not reported by the poll script:\n%s", script)
	}
	if strings.Contains(script, "catch {}") {
		t.Fatalf("poll script still swallows errors silently:\n%s", script)
	}
	if id, ok := parseMarker(toXMLFailPrefix+"884213", toXMLFailPrefix); !ok || id != 884213 {
		t.Fatalf("TOXMLFAIL marker not parsed: id=%d ok=%v", id, ok)
	}
	if _, ok := parseMarker(chanMaxPrefix+"1", toXMLFailPrefix); ok {
		t.Fatal("CHANMAX line must not parse as TOXMLFAIL")
	}
}

// The System EID 104 query runs only when asked (every clearCheckEvery polls),
// after $ErrorActionPreference is set, and without double quotes (the script
// is one -Command argument).
func TestPollScriptClearQuery(t *testing.T) {
	s := &sysmonRT{channel: "Microsoft-Windows-Sysmon/Operational", eids: defaultEIDs, maxPerPoll: 2000}
	if strings.Contains(s.pollScript(1, false), logClearedPrefix) {
		t.Fatal("clear query must not run when checkClears is false")
	}
	script := s.pollScript(1, true)
	if !strings.Contains(script, "EventID=104") || !strings.Contains(script, logClearedPrefix) {
		t.Fatalf("clear query missing:\n%s", script)
	}
	if strings.Index(script, "$ErrorActionPreference") > strings.Index(script, "EventID=104") {
		t.Fatalf("ErrorActionPreference must be set before the clear query:\n%s", script)
	}
	if strings.Contains(script, `"`) {
		t.Fatalf("script must not contain double quotes:\n%s", script)
	}
	if !strings.Contains(script, "timediff(@SystemTime) <= 86400000") {
		t.Fatalf("look-back is not 24h:\n%s", script)
	}
}

// LOGCLEARED payloads decode back to the record (base64 of UTF-16LE ToXml).
func TestDecodeLogCleared(t *testing.T) {
	u := utf16.Encode([]rune(eid104XML))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		b[2*i], b[2*i+1] = byte(v), byte(v>>8)
	}
	lc, err := decodeLogCleared(base64.StdEncoding.EncodeToString(b))
	if err != nil || lc.RecordID != 76219 || lc.Channel != "Microsoft-Windows-Sysmon/Operational" {
		t.Fatalf("decodeLogCleared: %+v err=%v", lc, err)
	}
}
