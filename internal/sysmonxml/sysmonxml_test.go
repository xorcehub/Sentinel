package sysmonxml

import (
	"testing"

	"sentinel/internal/event"
)

// Representative Sysmon EID 1 XML — the incident launch vector. Uses the real
// default xmlns so the host compile/test confirms namespace handling.
const eid1XML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST01</Computer>
    <Security UserID="S-1-5-..." />
    <TimeCreated SystemTime="2026-03-17T08:14:22.3140000Z" />
    <EventRecordID>48172</EventRecordID>
    <Execution ProcessID="1336" ThreadID="21032" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-03-17 08:14:22.314</Data>
    <Data Name="ProcessGuid">{abc-123}</Data>
    <Data Name="ProcessId">9204</Data>
    <Data Name="Image">C:\Windows\System32\conhost.exe</Data>
    <Data Name="CommandLine">conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\onedrive-sync.ps1"</Data>
    <Data Name="CurrentDirectory">C:\Users\user01\</Data>
    <Data Name="User">HOST01\user01</Data>
    <Data Name="Hashes">SHA256=deadbeef,IMPHASH=cafebabe</Data>
    <Data Name="ParentProcessGuid">{parent}</Data>
    <Data Name="ParentProcessId">7788</Data>
    <Data Name="ParentImage">C:\Windows\Explorer.EXE</Data>
    <Data Name="ParentCommandLine">explorer.exe</Data>
    <Data Name="SomeUnknownNewField">ignored</Data>
  </EventData>
</Event>`

// EID 3 — loopback network connect (the driver→broker channel).
const eid3XML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>3</EventID>
    <TimeCreated SystemTime="2026-06-26T14:03:11.0000000Z" />
    <EventRecordID>50001</EventRecordID>
  </System>
  <EventData>
    <Data Name="Image">C:\Users\user01\Downloads\driver.exe</Data>
    <Data Name="DestinationIp">127.0.0.1</Data>
    <Data Name="DestinationPort">58172</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="User">HOST01\user01</Data>
  </EventData>
</Event>`

// EID 10 — lsass access (TargetImage is the victim).
const eid10XML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>10</EventID>
    <EventRecordID>50002</EventRecordID>
  </System>
  <EventData>
    <Data Name="SourceImage">C:\Users\user01\Downloads\probe.exe</Data>
    <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
    <Data Name="GrantedAccess">0x1010</Data>
  </EventData>
</Event>`

func TestParseEID1(t *testing.T) {
	ev, err := Parse([]byte(eid1XML), event.SrcSysmonRT)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ev.EID != 1 {
		t.Errorf("EID=%d want 1", ev.EID)
	}
	if ev.RecordID != 48172 {
		t.Errorf("RecordID=%d want 48172", ev.RecordID)
	}
	if ev.Image != `C:\Windows\System32\conhost.exe` {
		t.Errorf("Image=%q", ev.Image)
	}
	wantCmd := `conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\onedrive-sync.ps1"`
	if ev.CmdLine != wantCmd {
		t.Errorf("CmdLine=%q want %q", ev.CmdLine, wantCmd)
	}
	if ev.ParentImage != `C:\Windows\Explorer.EXE` {
		t.Errorf("ParentImage=%q", ev.ParentImage)
	}
	if ev.User != `HOST01\user01` {
		t.Errorf("User=%q", ev.User)
	}
	if ev.Hashes["SHA256"] != "deadbeef" || ev.Hashes["IMPHASH"] != "cafebabe" {
		t.Errorf("Hashes=%v", ev.Hashes)
	}
	if ev.Time.Year() != 2026 || ev.Time.Month().String() != "March" {
		t.Errorf("Time=%v want 2026-03", ev.Time)
	}
	// tolerance: unknown field ignored, no error
}

func TestParseEID3Loopback(t *testing.T) {
	ev, err := Parse([]byte(eid3XML), event.SrcSysmonRT)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ev.DstIP != "127.0.0.1" || ev.DstPort != 58172 {
		t.Errorf("net=%s:%d want 127.0.0.1:58172", ev.DstIP, ev.DstPort)
	}
	if ev.DstProto != "tcp" {
		t.Errorf("proto=%q", ev.DstProto)
	}
}

func TestParseEID10TargetImage(t *testing.T) {
	// Regression for the CRED-002 bug: EID 10 victim must land in TargetImage,
	// NOT TargetFile. The engine/evaluator must never have a TargetFile path
	// to mis-match here.
	ev, err := Parse([]byte(eid10XML), event.SrcSysmonRT)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ev.TargetImage != `C:\Windows\System32\lsass.exe` {
		t.Errorf("TargetImage=%q", ev.TargetImage)
	}
	if ev.TargetFile != "" {
		t.Errorf("EID 10 must not populate TargetFile; got %q (this is the CRED-002 bug shape)", ev.TargetFile)
	}
	if ev.SourceImage != `C:\Users\user01\Downloads\probe.exe` {
		t.Errorf("SourceImage=%q", ev.SourceImage)
	}
}

func TestParseMalformedIsError(t *testing.T) {
	if _, err := Parse([]byte("not xml at all"), event.SrcSysmonRT); err == nil {
		t.Error("malformed XML should return an error")
	}
}

func TestParseEmptyIsZero(t *testing.T) {
	// minimal valid doc with no EventData -> zero-value fields, no panic.
	const empty = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>7</EventID><EventRecordID>1</EventRecordID></System></Event>`
	ev, err := Parse([]byte(empty), event.SrcSysmonSweep)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ev.EID != 7 || ev.RecordID != 1 {
		t.Errorf("got EID=%d RID=%d", ev.EID, ev.RecordID)
	}
	if ev.Image != "" || ev.Hashes != nil {
		t.Errorf("expected zero fields; Image=%q Hashes=%v", ev.Image, ev.Hashes)
	}
	if ev.Source != event.SrcSysmonSweep {
		t.Errorf("source not propagated: %q", ev.Source)
	}
}
