//go:build windows

package ingest

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"

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
