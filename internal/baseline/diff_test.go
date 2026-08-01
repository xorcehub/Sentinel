package baseline

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"sentinel/internal/event"
)

// realHeader is the exact CSV header autorunsc64 -c -s -t emits.
const realHeader = "Time,Entry Location,Entry,Enabled,Category,Profile,Description,Signer,Company,Image Path,Version,Launch String"

// sampleCSV is a synthetic snapshot in the real schema, exercising the two
// tricky shapes seen in the operator's actual output: empty-Entry section
// headers (must be skipped) and the RtkAudUService Launch String with doubled
// inner quotes (must round-trip through encoding/csv correctly).
const sampleCSV = realHeader + "\n" +
	// row 1: section header - empty Entry, MUST be skipped by Parse
	"20240401-072632,HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\StartupPrograms,,,Logon,System-wide,,,,,,\n" +
	// row 2: real entry (rdpclip)
	"20260615-072008,HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\StartupPrograms,rdpclip,enabled,Logon,System-wide,RDP Clipboard Monitor,(Verified) Microsoft Windows,(Verified) Microsoft Windows,C:\\WINDOWS\\system32\\rdpclip.exe,10.0.26100.8655,rdpclip\n" +
	// row 3: section header for Run - skipped
	"20260304-160219,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,,,Logon,System-wide,,,,,,\n" +
	// row 4: tricky Launch String with DOUBLED INNER QUOTES - ""C:\...\exe"" -background
	"20250930-114728,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,RtkAudUService,enabled,Logon,System-wide,Realtek HD Audio Universal Service,(Verified) Realtek Semiconductor Corp.,(Verified) Realtek Semiconductor Corp.,C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64_08ba31721ddee893\\RtkAudUService64.exe,1.1.730.1,\"\"\"C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64_08ba31721ddee893\\RtkAudUService64.exe\"\" -background\"\n" +
	// row 5: SecurityHealth entry
	"20260415-102744,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,SecurityHealth,enabled,Logon,System-wide,Windows Security notification icon,(Verified) Microsoft Windows,(Verified) Microsoft Windows,C:\\WINDOWS\\system32\\SecurityHealthSystray.exe,10.0.26100.8115,%windir%\\system32\\SecurityHealthSystray.exe\n" +
	// row 6: section header for Winlogon\Shell - skipped
	"20260629-064627,HKLM\\SOFTWARE\\Microsoft\\Windows\\NT\\CurrentVersion\\Winlogon\\Shell,,,Logon,System-wide,,,,,,\n"

func mustParse(t *testing.T, csv string) Snapshot {
	t.Helper()
	s, err := Parse(strings.NewReader(csv), time.Now())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

// TestParseSkipsSectionHeaders: the empty-Entry rows MUST be dropped, or every
// location that flips empty<->populated would generate diff noise. With the
// sample (6 CSV rows, 3 are section headers), Parse must return 3 entries.
func TestParseSkipsSectionHeaders(t *testing.T) {
	s := mustParse(t, sampleCSV)
	if len(s.Entries) != 3 {
		t.Fatalf("want 3 entries (section headers skipped), got %d: %+v", len(s.Entries), s.Entries)
	}
	for _, e := range s.Entries {
		if e.Entry == "" {
			t.Errorf("section header leaked into snapshot: %+v", e)
		}
	}
}

// TestParseHandlesQuotedLaunchString: the RtkAudUService row has a Launch String
// containing doubled inner quotes. encoding/csv must decode this to the literal
// value with single quotes - if a naive parser left doubled quotes or broke the
// field, the diff would mis-identify the entry. This is the edge case from the
// operator's real output.
func TestParseHandlesQuotedLaunchString(t *testing.T) {
	s := mustParse(t, sampleCSV)
	var rtk Entry
	for _, e := range s.Entries {
		if e.Entry == "RtkAudUService" {
			rtk = e
		}
	}
	if rtk.Entry == "" {
		t.Fatal("RtkAudUService entry not found")
	}
	want := `"C:\WINDOWS\System32\DriverStore\FileRepository\realtekservice.inf_amd64_08ba31721ddee893\RtkAudUService64.exe" -background`
	if rtk.Launch != want {
		t.Errorf("Launch String mis-parsed on quoted row:\n got: %q\nwant: %q", rtk.Launch, want)
	}
	if rtk.Signer != "(Verified) Realtek Semiconductor Corp." {
		t.Errorf("Signer = %q", rtk.Signer)
	}
}

// TestParseToleratesSchemaGrowth: a future autorunsc adding a column must not
// silently shift our reads. FieldsPerRecord=-1 + name-based lookup handle this,
// and this test pins it (extra column "VT" appended; reads still correct).
func TestParseToleratesSchemaGrowth(t *testing.T) {

	csv := "Time,Entry Location,Entry,Enabled,Category,Profile,Description,Signer,Company,Image Path,Version,Launch String,VT\n" +
		"20260101-000000,HKCU\\Run,TestEntry,enabled,Logon,user01,D,S,S,C:\\x.exe,1.0,x,clean\n"
	s := mustParse(t, csv)
	if len(s.Entries) != 1 || s.Entries[0].Entry != "TestEntry" {
		t.Fatalf("schema growth broke parse: %+v", s.Entries)
	}
	if s.Entries[0].ImagePath != "C:\\x.exe" {
		t.Errorf("Image Path mis-read with extra column: %q", s.Entries[0].ImagePath)
	}
}

// TestParseToleratesBareQuotesInUnquotedField: autorunsc emits NON-RFC-compliant
// CSV for unsigned entries - the Signer/Company fields contain literal " chars
// but the field itself is NOT quoted, e.g.:
//
//	...(Not verified) (Not Verified) Igor Pavlov,(Not Verified) Igor Pavlov,...
//
// Strict encoding/csv rejects this ('bare " in non-quoted-field'); LazyQuotes
// accepts it. This is the real-world failure that broke the first on-host
// --baseline-snapshot run (7-Zip shell extension rows). Pinned here so a future
// Go tightening or a revert of LazyQuotes surfaces immediately.
func TestParseToleratesBareQuotesInUnquotedField(t *testing.T) {
	csvText := realHeader + "\n" +
		// A 7-Zip ContextMenuHandlers row verbatim in shape: bare " in Signer+Company.
		"20260212-100000,HKLM\\Software\\Classes\\*\\ShellEx\\ContextMenuHandlers,7-Zip,enabled,Explorer,System-wide,7-Zip Shell Extension,(Not verified) (Not Verified) Igor Pavlov,(Not Verified) Igor Pavlov,C:\\Program Files\\7-Zip\\7-zip.dll,26.0.0.0,C:\\Program Files\\7-Zip\\7-zip.dll\n"
	s, err := Parse(strings.NewReader(csvText), time.Now())
	if err != nil {
		t.Fatalf("Parse must tolerate bare quotes (LazyQuotes): %v", err)
	}
	if len(s.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d: %+v", len(s.Entries), s.Entries)
	}
	e := s.Entries[0]
	if e.Entry != "7-Zip" {
		t.Errorf("Entry = %q", e.Entry)
	}
	if e.Signer != "(Not verified) (Not Verified) Igor Pavlov" {
		t.Errorf("Signer = %q (bare quotes must be preserved verbatim)", e.Signer)
	}
	if e.ImagePath != "C:\\Program Files\\7-Zip\\7-zip.dll" {
		t.Errorf("ImagePath = %q (the bare quotes must not have shifted field reads)", e.ImagePath)
	}
}

// TestParseDecodesUTF16LE: autorunsc64.exe emits UTF-16 LE (BOM FF FE) on
// Windows. Without BOM-sniffing + decode, encoding/csv sees 'T\x00i\x00m\x00e'
// as the header, matches nothing, and Parse returns zero entries - the live
// on-host bug (clean=0, daily=0). This test feeds a UTF-16LE-encoded sample
// with BOM and asserts the entries decode correctly.
func TestParseDecodesUTF16LE(t *testing.T) {
	// Encode sampleCSV as UTF-16 LE with BOM.
	u16 := encodeUTF16LE(sampleCSV)
	s, err := Parse(bytes.NewReader(u16), time.Now())
	if err != nil {
		t.Fatalf("Parse must decode UTF-16LE: %v", err)
	}
	if len(s.Entries) != 3 {
		t.Errorf("want 3 entries (BOM/UTF-16 decode must not lose rows), got %d", len(s.Entries))
	}
	// Spot-check one entry decoded correctly (not as 'T\x00i\x00m\x00e').
	for _, e := range s.Entries {
		if e.Entry == "rdpclip" {
			if e.ImagePath != "C:\\WINDOWS\\system32\\rdpclip.exe" {
				t.Errorf("ImagePath mis-decoded from UTF-16: %q", e.ImagePath)
			}
			return
		}
	}
	t.Errorf("rdpclip entry not found in UTF-16LE parse")
}

// encodeUTF16LE returns b as UTF-16 LE bytes with a FF FE BOM, mirroring what
// autorunsc64 writes. Test helper only.
func encodeUTF16LE(b string) []byte {
	runes := []rune(b)
	codes := utf16.Encode(runes)
	out := []byte{0xFF, 0xFE}
	for _, c := range codes {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

// TestDiffEmpty: identical snapshots produce no events (steady state - clean
// machine, no new persistence).
func TestDiffEmpty(t *testing.T) {
	s := mustParse(t, sampleCSV)
	if got := Diff(s, s); len(got) != 0 {
		t.Errorf("identical snapshots should diff to nothing, got %d events", len(got))
	}
}

// TestDiffNewEntry: the headline case - a new Run-key value appears in daily.
// Must yield one baseline event with Source=baseline, the location\name in
// TargetRegKey (registry-backed), and the launch string in CmdLine.
func TestDiffNewEntry(t *testing.T) {
	clean := mustParse(t, sampleCSV)
	// daily = clean + one new entry (the attacker)
	dailyCSV := sampleCSV +
		"20260629-140000,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,EvilUpdate,enabled,Logon,System-wide,Evil Updater,(Not verified) EvilCorp,EvilCorp,C:\\ProgramData\\evil.exe,1.0,C:\\ProgramData\\evil.exe /silent\n"
	daily := mustParse(t, dailyCSV)

	events := Diff(clean, daily)
	if len(events) != 1 {
		t.Fatalf("want 1 new-entry event, got %d: %+v", len(events), events)
	}
	e := events[0]
	if e.Source != event.SrcBaseline {
		t.Errorf("Source = %q, want %q", e.Source, event.SrcBaseline)
	}
	wantReg := `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilUpdate`
	if e.TargetRegKey != wantReg {
		t.Errorf("TargetRegKey = %q, want %q", e.TargetRegKey, wantReg)
	}
	if e.CmdLine != `C:\ProgramData\evil.exe /silent` {
		t.Errorf("CmdLine = %q", e.CmdLine)
	}
	if e.Image != `C:\ProgramData\evil.exe` {
		t.Errorf("Image = %q", e.Image)
	}
	if e.User != "(Not verified) EvilCorp" {
		t.Errorf("User (signer) = %q", e.User)
	}
}

// TestDiffEntriesReturnsEntries: DiffEntries (the daemon's alert-once gate
// depends on it) returns the raw NEW entries — not events — sorted, so the
// caller can dedup on Entry.Key() before converting. EntriesToEvents then
// produces one event per survivor with the same shape as Diff().
func TestDiffEntriesReturnsEntries(t *testing.T) {
	clean := mustParse(t, sampleCSV)
	daily := mustParse(t, sampleCSV+
		"20260629-120000,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,BrandNew,enabled,Logon,System-wide,Brand New App,(Verified) Corp,(Verified) Corp,C:\\Program Files\\bn\\bn.exe,1.0,\"C:\\Program Files\\bn\\bn.exe\"\n")

	entries := DiffEntries(clean, daily)
	if len(entries) != 1 {
		t.Fatalf("DiffEntries: want 1, got %d", len(entries))
	}
	if entries[0].Entry != "BrandNew" {
		t.Errorf("Entry = %q, want BrandNew", entries[0].Entry)
	}
	// The key is what the daemon's alert-once gate hashes on.
	wantKey := `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` + "\x00" + "BrandNew"
	if entries[0].Key() != wantKey {
		t.Errorf("Key = %q, want %q", entries[0].Key(), wantKey)
	}
	// EntriesToEvents produces the same event shape as Diff for the same input.
	evs := EntriesToEvents(entries)
	if len(evs) != 1 || evs[0].Source != event.SrcBaseline {
		t.Errorf("EntriesToEvents: got %+v", evs)
	}
	// Equivalence with the convenience wrapper Diff().
	if got := len(Diff(clean, daily)); got != 1 {
		t.Errorf("Diff wrapper: want 1, got %d", got)
	}
}

// TestDiffUpdateIsNotNew: a Discord-style update (new Time/Signer/Version but
// same Location+Entry) MUST NOT fire - the identity Key is Location+Entry, so a
// re-sign on update is suppressed. Without this, the diff would toast-flood on
// every app update.
func TestDiffUpdateIsNotNew(t *testing.T) {
	clean := mustParse(t, sampleCSV)
	// daily = same entries but RtkAudUService got a new timestamp + version
	// (simulating an update). Key unchanged -> no event.
	dailyCSV := strings.Replace(sampleCSV,
		"20250930-114728,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,RtkAudUService,enabled,Logon,System-wide,Realtek HD Audio Universal Service,(Verified) Realtek Semiconductor Corp.,(Verified) Realtek Semiconductor Corp.,C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64_08ba31721ddee893\\RtkAudUService64.exe,1.1.730.1,",
		"20260629-120000,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,RtkAudUService,enabled,Logon,System-wide,Realtek HD Audio Universal Service (updated),(Verified) Realtek Semiconductor Corp.,(Verified) Realtek Semiconductor Corp.,C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64_08ba31721ddee893\\RtkAudUService64.exe,1.1.731.0,",
		1)
	daily := mustParse(t, dailyCSV)
	if got := Diff(clean, daily); len(got) != 0 {
		t.Errorf("an update with same Location+Entry must NOT fire; got %d: %+v", len(got), got)
	}
}

// TestDiffRemovedIgnored: removed entries must NOT emit events (uninstallers
// remove things constantly; the threat model is "new persistence appeared").
func TestDiffRemovedIgnored(t *testing.T) {
	clean := mustParse(t, sampleCSV)
	// daily = clean minus the whole SecurityHealth line. We replace the FULL
	// line (including its trailing newline), not just a prefix - replacing only
	// the prefix would leave ",Logon,System-wide,..." dangling as a malformed
	// new row, which the parser would then keep as a spurious entry.
	secHealthLine := "20260415-102744,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,SecurityHealth,enabled,Logon,System-wide,Windows Security notification icon,(Verified) Microsoft Windows,(Verified) Microsoft Windows,C:\\WINDOWS\\system32\\SecurityHealthSystray.exe,10.0.26100.8115,%windir%\\system32\\SecurityHealthSystray.exe\n"
	dailyCSV := strings.Replace(sampleCSV, secHealthLine, "", 1)
	if dailyCSV == sampleCSV {
		t.Fatal("test setup failure: SecurityHealth line not found verbatim in sampleCSV")
	}
	daily := mustParse(t, dailyCSV)
	if got := Diff(clean, daily); len(got) != 0 {
		t.Errorf("removed entries should not emit events, got %d: %+v", len(got), got)
	}
}

// TestDiffDeterministicOrder: repeated diffs of the same input produce events
// in the same order. Critical for review and for the test itself to be stable.
func TestDiffDeterministicOrder(t *testing.T) {
	dailyCSV := sampleCSV +
		"20260629-140000,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,Zeta,enabled,Logon,System-wide,Z,Z,S,S,C:\\z.exe,1.0,z\n" +
		"20260629-140001,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,Alpha,enabled,Logon,System-wide,A,A,S,S,C:\\a.exe,1.0,a\n" +
		"20260629-140002,HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,Mike,enabled,Logon,user01,M,M,S,S,C:\\m.exe,1.0,m\n"
	daily := mustParse(t, dailyCSV)
	first := Diff(mustParse(t, sampleCSV), daily)
	second := Diff(mustParse(t, sampleCSV), daily)
	if len(first) != 3 {
		t.Fatalf("want 3 new entries, got %d", len(first))
	}
	// sorted by Location then Entry: HKCU\Mike, HKLM\Alpha, HKLM\Zeta
	want := []string{
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Mike`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Alpha`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Zeta`,
	}
	for i, w := range want {
		if first[i].TargetRegKey != w {
			t.Errorf("order[%d]: got %q, want %q", i, first[i].TargetRegKey, w)
		}
		if first[i].TargetRegKey != second[i].TargetRegKey {
			t.Errorf("non-deterministic: run1[%d]=%q run2[%d]=%q", i, first[i].TargetRegKey, i, second[i].TargetRegKey)
		}
	}
}

// TestDiffFilesystemLocationUsesTargetFile: a Startup-folder entry is NOT
// registry-backed, so the alert should land in TargetFile, not TargetRegKey.
func TestDiffFilesystemLocationUsesTargetFile(t *testing.T) {
	clean := mustParse(t, "Time,Entry Location,Entry,Enabled,Category,Profile,Description,Signer,Company,Image Path,Version,Launch String\n")
	daily := mustParse(t, "Time,Entry Location,Entry,Enabled,Category,Profile,Description,Signer,Company,Image Path,Version,Launch String\n"+
		"20260629-140000,C:\\Users\\user01\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup,evil.lnk,enabled,Logon,user01,evil,,EvilCorp,C:\\ProgramData\\evil.exe,1.0,C:\\ProgramData\\evil.exe\n")
	events := Diff(clean, daily)
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].TargetRegKey != "" {
		t.Errorf("filesystem location should not set TargetRegKey: %q", events[0].TargetRegKey)
	}
	if events[0].TargetFile == "" {
		t.Errorf("filesystem location should set TargetFile")
	}
}

// TestDiffPerUserServiceSuffixRotation: Windows per-user services register a
// bare template (cbdhsvc) plus a per-session instance whose _<hex> suffix
// rotates every logon/user. A legit service must NOT churn as new persistence
// when only the suffix changed. Conversely, a hex-tailed name whose base is NOT
// one of the documented per-user families MUST stay flagged — whether it has no
// template (HWiNFO_214) or mimics a real family name (PrintWorkflowSvc_deadbeef
// vs the real PrintWorkflowUserSvc). Safety = family membership, not suffix shape.
func TestDiffPerUserServiceSuffixRotation(t *testing.T) {
	const svcLoc = `HKLM\System\CurrentControlSet\Services`
	// Fields kept comma-free so no CSV quoting is needed; only Key() semantics matter.
	row := func(entry string) string {
		return "20260723-090000," + svcLoc + "," + entry + ",enabled,Services,System-wide,svc,(Verified) Microsoft Windows,(Verified) Microsoft Windows,C:\\WINDOWS\\system32\\svchost.exe,10.0,svchost.exe\n"
	}
	// clean: bare per-user service templates + a versioned service with NO family match.
	cleanCSV := sampleCSV +
		row("cbdhsvc") +
		row("WpnUserService") +
		row("PrintWorkflowUserSvc") + // real family
		row("HWiNFO_214")
	clean := mustParse(t, cleanCSV)
	// daily: clean + (a) rotated cbdhsvc suffix (real family -> suppressed),
	// (b) PrintWorkflowSvc_deadbeef mimicking the real PrintWorkflowUserSvc but
	// NOT a family member -> must flag, and (c) BackdoorSvc_123456 -> must flag.
	daily := mustParse(t, cleanCSV+
		row("cbdhsvc_f62dc")+
		row("PrintWorkflowSvc_deadbeef")+
		row("BackdoorSvc_123456"))

	events := Diff(clean, daily)
	got := map[string]bool{}
	for _, ev := range events {
		got[ev.TargetRegKey] = true
	}
	// Exactly two NEW events: the mimic and the backdoor. cbdhsvc_f62dc must be
	// suppressed (real family); HWiNFO_214 and the bare templates are identical.
	if len(events) != 2 {
		t.Fatalf("want exactly 2 new events (PrintWorkflowSvc_deadbeef, BackdoorSvc_123456); got %d: %v",
			len(events), got)
	}
	for _, want := range []string{"PrintWorkflowSvc_deadbeef", "BackdoorSvc_123456"} {
		found := false
		for k := range got {
			if strings.Contains(k, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s must FLAG (not suppressed); events were %v", want, got)
		}
	}
	// cbdhsvc_f62dc must NOT appear — it's a real per-user family rotation.
	for k := range got {
		if strings.Contains(k, "cbdhsvc_f62dc") {
			t.Errorf("cbdhsvc_f62dc (real family rotation) must be suppressed; got %q", k)
		}
	}
}
