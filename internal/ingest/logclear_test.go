package ingest

import (
	"strings"
	"testing"
	"time"

	"sentinel/internal/event"
)

// Real System EID 104 ToXml() captured live (hostname and SID replaced) after
// `wevtutil cl Microsoft-Windows-Sysmon/Operational /bu:...` (2026-11-07).
const eid104XML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>104</EventID><Version>1</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-07T22:02:40.6929341Z'/><EventRecordID>76219</EventRecordID><Correlation/><Execution ProcessID='4776' ThreadID='22268'/><Channel>System</Channel><Computer>DESKTOP-TEST</Computer><Security UserID='S-1-5-21-1000000000-1000000000-1000000000-1001'/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>jurij</SubjectUserName><SubjectDomainName>DESKTOP-TEST</SubjectDomainName><Channel>Microsoft-Windows-Sysmon/Operational</Channel><BackupPath>C:\SysmonBackup\sysmon-20261107-230238.evtx</BackupPath><ClientProcessId>20496</ClientProcessId><ClientProcessStartKey>62487444829795886</ClientProcessStartKey></LogFileCleared></UserData></Event>`

const sysmonChannel = "Microsoft-Windows-Sysmon/Operational"

func TestParseLogCleared(t *testing.T) {
	lc, err := parseLogCleared([]byte(eid104XML))
	if err != nil {
		t.Fatal(err)
	}
	want := logClear{
		RecordID:  76219,
		Time:      time.Date(2026, 11, 7, 22, 2, 40, 692934100, time.UTC),
		Channel:   sysmonChannel,
		User:      `DESKTOP-TEST\jurij`,
		Backup:    `C:\SysmonBackup\sysmon-20261107-230238.evtx`,
		ClientPID: "20496",
	}
	if !lc.Time.Equal(want.Time) {
		t.Fatalf("time = %v, want %v", lc.Time, want.Time)
	}
	lc.Time = want.Time
	if lc != want {
		t.Fatalf("parsed\n got %+v\nwant %+v", lc, want)
	}
	if _, err := parseLogCleared([]byte(`<Event><System><EventRecordID>1</EventRecordID></System></Event>`)); err == nil {
		t.Fatal("record without a Channel must be rejected")
	}
}

// The synthetic event carries what TELEMETRY-002 selects on, and the System
// RecordId in Details so the rule's Details dedup key is unique per clear.
func TestLogClearedEventShape(t *testing.T) {
	lc, _ := parseLogCleared([]byte(eid104XML))
	ev := logClearedEvent(lc)
	if ev.Source != event.SrcSentinel || ev.EID != 0 || ev.Image != sysmonChannel || ev.User != `DESKTOP-TEST\jurij` {
		t.Fatalf("bad synthetic event: %+v", ev)
	}
	for _, want := range []string{event.DetailsSysmonCleared + " ", "system_record_id=76219", `by=DESKTOP-TEST\jurij`, `backup=C:\SysmonBackup\`} {
		if !strings.Contains(ev.Details, want) {
			t.Fatalf("Details missing %q: %q", want, ev.Details)
		}
	}
	if !strings.HasPrefix(ev.Details, event.DetailsSysmonCleared) {
		t.Fatalf("Details must start with the rule prefix: %q", ev.Details)
	}
}

// Each clear of OUR channel is emitted once per run, other channels never;
// the look-back re-reads the same records every check.
func TestClearTrackerFresh(t *testing.T) {
	now := time.Date(2026, 11, 7, 23, 0, 0, 0, time.UTC)
	a := logClear{RecordID: 10, Time: now.Add(-2 * time.Hour), Channel: sysmonChannel}
	b := logClear{RecordID: 11, Time: now.Add(-time.Hour), Channel: "Application"}
	c := logClear{RecordID: 12, Time: now.Add(-time.Minute), Channel: strings.ToLower(sysmonChannel)}
	var ct clearTracker
	got := ct.fresh([]logClear{a, b, c}, sysmonChannel, now)
	if len(got) != 2 || got[0].RecordID != 10 || got[1].RecordID != 12 {
		t.Fatalf("first check: got %+v, want records 10 and 12", got)
	}
	if got := ct.fresh([]logClear{a, b, c}, sysmonChannel, now.Add(10*time.Second)); len(got) != 0 {
		t.Fatalf("re-read of the same records must emit nothing, got %+v", got)
	}
	d := logClear{RecordID: 13, Time: now.Add(time.Minute), Channel: sysmonChannel}
	if got := ct.fresh([]logClear{a, c, d}, sysmonChannel, now.Add(time.Minute)); len(got) != 1 || got[0].RecordID != 13 {
		t.Fatalf("new clear: got %+v, want record 13", got)
	}
	ct.fresh(nil, sysmonChannel, now.Add(clearLookback+30*time.Minute))
	if len(ct.seen) != 2 { // a (26h30m old) pruned; c and d still inside look-back + 1h
		t.Fatalf("old entries not pruned: %d left", len(ct.seen))
	}
}
