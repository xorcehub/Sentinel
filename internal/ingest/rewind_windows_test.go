//go:build windows

package ingest

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"sentinel/internal/event"
)

// A recreated channel restarts RecordIds at 1; without the rewind check the
// operator would never learn the history before it is gone.
func TestRecordIDsRewound(t *testing.T) {
	cases := []struct {
		id, highWater int64
		want          bool
	}{
		{12, 884213, true},      // channel recreated, new records below the high-water
		{884213, 884213, false}, // nothing new
		{884300, 884213, false}, // normal progress
		{-1, 884213, false},     // no id: unknown, not a rewind
		{5, -1, false},          // first record after start: nothing consumed yet
		{0, 1, true},            // degenerate but still backwards
	}
	for _, c := range cases {
		if got := recordIDsRewound(c.id, c.highWater); got != c.want {
			t.Errorf("recordIDsRewound(%d, %d) = %v, want %v", c.id, c.highWater, got, c.want)
		}
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

// Undecodable records must be counted and logged, not skipped silently.
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

// The subscription query must select exactly defaultEIDs, and the log-clear
// query must look back 24h for System EID 104 from the Eventlog provider.
func TestQueries(t *testing.T) {
	q := defaultEIDQuery()
	for _, id := range defaultEIDs {
		if !strings.Contains(q, fmt.Sprintf("EventID=%d)", id)) && !strings.Contains(q, fmt.Sprintf("EventID=%d or", id)) {
			t.Errorf("EID %d missing from query %q", id, q)
		}
	}
	if !strings.HasPrefix(q, "*[System[(") || !strings.HasSuffix(q, ")]]") {
		t.Errorf("malformed query %q", q)
	}
	lq := logClearsQuery()
	for _, want := range []string{"EventID=104", "Microsoft-Windows-Eventlog", "timediff(@SystemTime) <= 86400000"} {
		if !strings.Contains(lq, want) {
			t.Errorf("log-clear query %q missing %q", lq, want)
		}
	}
}
