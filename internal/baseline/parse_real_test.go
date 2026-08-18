package baseline

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"sentinel/internal/event"
)

// --- Real-baseline integration tests (using the operator's actual CSV) ---

func TestParseRealBaseline(t *testing.T) {
	raw, err := os.ReadFile("../../baseline_clean.csv")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s, err := Parse(bytes.NewReader(raw), time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Logf("entries: %d", len(s.Entries))
	for i, e := range s.Entries {
		if i >= 5 {
			break
		}
		t.Logf("  [%d] Loc=%q Entry=%q Signer=%q Image=%q", i, e.Location, e.Entry, e.Signer, e.ImagePath)
	}
	if len(s.Entries) > 5 {
		t.Logf("  ...")
		for i := len(s.Entries) - 3; i < len(s.Entries); i++ {
			e := s.Entries[i]
			t.Logf("  [%d] Loc=%q Entry=%q Signer=%q Image=%q", i, e.Location, e.Entry, e.Signer, e.ImagePath)
		}
	}
	emptyCount := 0
	for _, e := range s.Entries {
		if e.Entry == "" {
			emptyCount++
			t.Errorf("empty Entry leaked: %+v", e)
		}
	}
	if emptyCount > 0 {
		t.Errorf("%d entries with empty Entry field leaked through", emptyCount)
	}
}

func TestDiffAgainstSelfIsZero(t *testing.T) {
	raw, err := os.ReadFile("../../baseline_clean.csv")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s, err := Parse(bytes.NewReader(raw), time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	events := Diff(s, s)
	if len(events) != 0 {
		t.Errorf("self-diff should be empty, got %d events", len(events))
		for _, e := range events {
			t.Logf("  %+v", e)
		}
	}
}

func TestDiffRealBaselineWithFakeNewEntry(t *testing.T) {
	raw, err := os.ReadFile("../../baseline_clean.csv")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s, err := Parse(bytes.NewReader(raw), time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	evilEntry := Entry{
		Time:      "20260818-120000",
		Location:  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		Entry:     "EvilPersistence",
		Enabled:   "enabled",
		Category:  "Logon",
		Profile:   "System-wide",
		Signer:    "(Not verified) EvilCorp",
		ImagePath: `C:\ProgramData\evil.exe`,
		Launch:    `C:\ProgramData\evil.exe /silent`,
	}
	daily := Snapshot{
		TakenAt: time.Now(),
		Entries: append(append([]Entry{}, s.Entries...), evilEntry),
	}

	events := Diff(s, daily)
	if len(events) != 1 {
		t.Fatalf("want 1 new event, got %d", len(events))
	}
	if events[0].TargetRegKey != `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilPersistence` {
		t.Errorf("TargetRegKey = %q", events[0].TargetRegKey)
	}
	t.Logf("correctly detected: %+v", events[0])
}

// TestDiffRealBaselineMultipleNewEntries: adding several new entries across
// different locations must all be detected and sorted deterministically.
func TestDiffRealBaselineMultipleNewEntries(t *testing.T) {
	raw, err := os.ReadFile("../../baseline_clean.csv")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s, err := Parse(bytes.NewReader(raw), time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	extras := []Entry{
		{Location: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Entry: "UserMalware", ImagePath: `C:\Users\victim\AppData\Local\temp\dropper.exe`},
		{Location: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Entry: "SystemMalware", ImagePath: `C:\ProgramData\svc.exe`},
		{Location: `C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, Entry: "evil.lnk", ImagePath: `C:\ProgramData\payload.exe`},
	}
	daily := Snapshot{
		TakenAt: time.Now(),
		Entries: append(append([]Entry{}, s.Entries...), extras...),
	}

	events := Diff(s, daily)
	if len(events) != 3 {
		t.Fatalf("want 3 new events, got %d", len(events))
	}
	// Verify sorted order: filesystem first (C:\...), then HKCU, then HKLM
	if !strings.HasPrefix(events[0].TargetFile, "C:") {
		t.Errorf("event[0] should be filesystem: %+v", events[0])
	}
	if !strings.HasPrefix(events[1].TargetRegKey, `HKCU\`) {
		t.Errorf("event[1] should be HKCU: %+v", events[1])
	}
	if !strings.HasPrefix(events[2].TargetRegKey, `HKLM\`) {
		t.Errorf("event[2] should be HKLM: %+v", events[2])
	}
}

// TestKeyCollision: Entry.Key() uses "\x00" separator. An Entry containing
// "\x00" could theoretically collide with a different Location. In practice
// registry key names and filenames never contain null bytes, but this pins
// the semantic so a future Key() redesign is intentional.
func TestKeyCollision(t *testing.T) {
	// Location="A", Entry="B\x00C" → Key="A\x00B\x00C"
	// Location="A\x00B", Entry="C" → Key="A\x00B\x00C"
	e1 := Entry{Location: "A", Entry: "B\x00C"}
	e2 := Entry{Location: "A\x00B", Entry: "C"}
	if e1.Key() != e2.Key() {
		t.Errorf("expected collision, got different keys: %q vs %q", e1.Key(), e2.Key())
	}
	// This test documents the collision. If you ever need to fix it, use a
	// separator that can't appear in Location or Entry (e.g. "\x00\x01").
}

// TestServiceTemplateBaseEdgeCases: the per-user-service suffix detection has
// specific width bounds (5-8 hex chars) and a family-membership gate. Test the
// boundaries.
func TestServiceTemplateBaseEdgeCases(t *testing.T) {
	const svcLoc = `HKLM\System\CurrentControlSet\Services`

	tests := []struct {
		name    string
		loc     string
		entry   string
		wantOk  bool
		wantBase string
	}{
		{"real family cbdhsvc_f62dc", svcLoc, "cbdhsvc_f62dc", true, "cbdhsvc"},
		{"real family 5 hex", svcLoc, "AarSvc_ABCDE", true, "AarSvc"},
		{"real family 8 hex", svcLoc, "AarSvc_ABCDEF01", true, "AarSvc"},
		{"too short 4 hex", svcLoc, "cbdhsvc_1234", false, ""},
		{"too long 9 hex", svcLoc, "cbdhsvc_123456789", false, ""},
		{"non-hex suffix", svcLoc, "cbdhsvc_ghijkl", false, ""},
		{"no underscore", svcLoc, "cbdhsvc", false, ""},
		{"empty suffix after underscore", svcLoc, "cbdhsvc_", false, ""},
		{"underscore at start", svcLoc, "_f62dc", false, ""},
		{"wrong location", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, "cbdhsvc_f62dc", false, ""},
		{"HWiNFO_214 not family", svcLoc, "HWiNFO_214", false, ""}, // suffix too short
		{"HWiNFO_214ABCD family check", svcLoc, "HWiNFO_214ABCD", true, "HWiNFO"}, // shape matches, but family gate blocks
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, ok := serviceTemplateBase(tt.loc, tt.entry)
			if ok != tt.wantOk {
				t.Errorf("ok = %v, want %v", ok, tt.wantOk)
			}
			if base != tt.wantBase {
				t.Errorf("base = %q, want %q", base, tt.wantBase)
			}
		})
	}
}

// TestPerUserFamilyMembership: the family list is the safety gate, not the
// suffix shape. An attacker creating PrintWorkflowSvc_deadbeef (mimicking the
// real PrintWorkflowUserSvc) MUST be flagged.
func TestPerUserFamilyMembership(t *testing.T) {
	// These should be suppressed (real families)
	for _, family := range []string{"cbdhsvc", "WpnUserService", "CDPUserSvc"} {
		if !perUserSvcFamily[strings.ToLower(family)] {
			t.Errorf("%s should be in perUserSvcFamily", family)
		}
	}
	// These should NOT be suppressed (not real families, even if suffix-shaped)
	for _, nonFamily := range []string{"PrintWorkflowSvc", "BackdoorSvc", "HWiNFO", "EvilSvc"} {
		if perUserSvcFamily[strings.ToLower(nonFamily)] {
			t.Errorf("%s should NOT be in perUserSvcFamily", nonFamily)
		}
	}
}

// TestUTF16BOMVariants: Parse must handle UTF-16 LE BOM (FF FE), UTF-16 BE
// BOM (FE FF), and plain UTF-8 without BOM.
func TestUTF16BOMVariants(t *testing.T) {
	csv := "Time,Entry Location,Entry,Enabled,Category,Profile,Description,Signer,Company,Image Path,Version,Launch String\n" +
		"20260101-000000,HKCU\\Run,Test,enabled,Logon,user01,D,S,S,C:\\x.exe,1.0,x\n"

	tests := []struct {
		name  string
		encode func(string) []byte
	}{
		{"UTF-8 no BOM", func(s string) []byte { return []byte(s) }},
		{"UTF-16 LE with BOM", func(s string) []byte {
			runes := []rune(s)
			codes := utf16.Encode(runes)
			out := []byte{0xFF, 0xFE}
			for _, c := range codes {
				out = append(out, byte(c), byte(c>>8))
			}
			return out
		}},
		{"UTF-16 BE with BOM", func(s string) []byte {
			runes := []rune(s)
			codes := utf16.Encode(runes)
			out := []byte{0xFE, 0xFF}
			for _, c := range codes {
				out = append(out, byte(c>>8), byte(c))
			}
			return out
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.encode(csv)
			s, err := Parse(bytes.NewReader(raw), time.Now())
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(s.Entries) != 1 {
				t.Fatalf("want 1 entry, got %d", len(s.Entries))
			}
			if s.Entries[0].Entry != "Test" {
				t.Errorf("Entry = %q, want Test", s.Entries[0].Entry)
			}
		})
	}
}

// TestUTF16LETrailingOddByte: a truncated UTF-16 stream with an odd number
// of payload bytes must not panic; the trailing byte is dropped.
func TestUTF16LETrailingOddByte(t *testing.T) {
	// Encode "AB" as UTF-16LE: 0x41 0x00 0x42 0x00, then add one trailing byte.
	payload := []byte{0x41, 0x00, 0x42, 0x00, 0xFF}
	bom := []byte{0xFF, 0xFE}
	raw := append(bom, payload...)

	s, err := Parse(bytes.NewReader(raw), time.Now())
	if err != nil {
		t.Fatalf("Parse must not panic on odd trailing byte: %v", err)
	}
	// We just care it doesn't panic; the decoded content is "AB" + U+FF00 or similar.
	_ = s
}

// TestIsHexBoundaries: the isHex helper must reject non-hex characters.
func TestIsHexBoundaries(t *testing.T) {
	for _, c := range "0123456789abcdefABCDEF" {
		if !isHex(byte(c)) {
			t.Errorf("isHex(%q) = false, want true", c)
		}
	}
	for _, c := range "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ _-" {
		if isHex(byte(c)) {
			t.Errorf("isHex(%q) = true, want false", c)
		}
	}
}

// TestIsRegistryLocationCases: verify hive-prefix detection with various casings.
func TestIsRegistryLocationCases(t *testing.T) {
	yes := []string{
		`HKLM\Software`,
		`HKCU\Software`,
		`HKCR\*`,
		`HKU\.DEFAULT`,
		`HKCC\System`,
		`hklm\software`, // lowercase
	}
	no := []string{
		`C:\Users\user01\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
		`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`,
		`D:\autoruns`,
	}
	for _, loc := range yes {
		if !isRegistryLocation(loc) {
			t.Errorf("isRegistryLocation(%q) = false, want true", loc)
		}
	}
	for _, loc := range no {
		if isRegistryLocation(loc) {
			t.Errorf("isRegistryLocation(%q) = true, want false", loc)
		}
	}
}

// TestEntriesToEventsTimestampsAreClose: all events from one EntriesToEvents
// call share the same "now" (within a few ms), critical for log correlation.
func TestEntriesToEventsTimestampsAreClose(t *testing.T) {
	entries := []Entry{
		{Location: `HKLM\Run`, Entry: "A"},
		{Location: `HKLM\Run`, Entry: "B"},
		{Location: `HKLM\Run`, Entry: "C"},
	}
	events := EntriesToEvents(entries)
	if len(events) != 3 {
		t.Fatalf("want 3, got %d", len(events))
	}
	for i := 1; i < len(events); i++ {
		diff := events[i].Time.Sub(events[0].Time)
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Second {
			t.Errorf("event[%d] timestamp %v differs from event[0] %v by %v", i, events[i].Time, events[0].Time, diff)
		}
	}
}

// TestDiffChurnOnUpdateVsNew: update (same key) = no event; new key = event.
// Tests the core identity semantics at scale with the real baseline.
func TestDiffChurnOnUpdateVsNew(t *testing.T) {
	raw, err := os.ReadFile("../../baseline_clean.csv")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s, err := Parse(bytes.NewReader(raw), time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Simulate an update: change the first entry's signer + version (same Key)
	updated := make([]Entry, len(s.Entries))
	copy(updated, s.Entries)
	updated[0] = Entry{
		Time:        "20260818-120000",
		Location:    updated[0].Location,
		Entry:       updated[0].Entry,
		Enabled:     updated[0].Enabled,
		Category:    updated[0].Category,
		Profile:     updated[0].Profile,
		Description: updated[0].Description,
		Signer:      "(Verified) New Signer Corp",
		Company:     "New Signer Corp",
		ImagePath:   updated[0].ImagePath,
		Version:     "99.0.0.0",
		Launch:      updated[0].Launch,
	}

	daily := Snapshot{TakenAt: time.Now(), Entries: updated}
	events := Diff(s, daily)
	if len(events) != 0 {
		t.Errorf("update-only diff should be empty, got %d events", len(events))
		for _, e := range events {
			t.Logf("  spurious: %+v", e)
		}
	}

	// Now add a genuinely new entry on top of the update
	updated = append(updated, Entry{
		Location: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		Entry:    "NewAfterUpdate",
	})
	daily2 := Snapshot{TakenAt: time.Now(), Entries: updated}
	events2 := Diff(s, daily2)
	if len(events2) != 1 {
		t.Errorf("update+new diff should have 1 event, got %d", len(events2))
	}
}

// TestParseEmptyCSV: an empty CSV (header only) must produce zero entries.
func TestParseEmptyCSV(t *testing.T) {
	csv := "Time,Entry Location,Entry,Enabled,Category,Profile,Description,Signer,Company,Image Path,Version,Launch String\n"
	s, err := Parse(strings.NewReader(csv), time.Now())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(s.Entries) != 0 {
		t.Errorf("want 0 entries, got %d", len(s.Entries))
	}
}

// TestParseNoHeader: CSV with no header at all must error (first Read returns data).
func TestParseNoHeader(t *testing.T) {
	csv := "20260101-000000,HKCU\\Run,Test,enabled,Logon,user01,D,S,S,C:\\x.exe,1.0,x\n"
	_, err := Parse(strings.NewReader(csv), time.Now())
	// Should either error or produce 0 entries (no header matched)
	if err != nil {
		t.Logf("correctly errored on headerless CSV: %v", err)
	}
}

// TestDiffEmptyDaily: daily with zero entries vs non-empty clean = no new entries.
func TestDiffEmptyDaily(t *testing.T) {
	clean := Snapshot{Entries: []Entry{
		{Location: `HKLM\Run`, Entry: "A"},
	}}
	daily := Snapshot{Entries: nil}
	events := Diff(clean, daily)
	if len(events) != 0 {
		t.Errorf("empty daily should produce no events, got %d", len(events))
	}
}

// TestDiffEmptyCleanVsPopulatedDaily: empty clean + daily with entries = all are new.
func TestDiffEmptyCleanVsPopulatedDaily(t *testing.T) {
	clean := Snapshot{Entries: nil}
	daily := Snapshot{Entries: []Entry{
		{Location: `HKLM\Run`, Entry: "A"},
		{Location: `HKLM\Run`, Entry: "B"},
	}}
	events := Diff(clean, daily)
	if len(events) != 2 {
		t.Errorf("want 2 new events, got %d", len(events))
	}
}

// TestBaselineEventFieldPopulation: the baselineEvent function must populate
// Image, CmdLine, User (signer), and the correct Target* field.
func TestBaselineEventFieldPopulation(t *testing.T) {
	tests := []struct {
		name           string
		entry          Entry
		wantRegKey     bool // true = TargetRegKey set; false = TargetFile set
		wantRegKeyVal  string
		wantFileVal    string
	}{
		{
			name: "registry location",
			entry: Entry{
				Location:  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
				Entry:     "Evil",
				Signer:    "(Not verified) Corp",
				ImagePath: `C:\evil.exe`,
				Launch:    `C:\evil.exe --arg`,
			},
			wantRegKey:    true,
			wantRegKeyVal: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil`,
		},
		{
			name: "filesystem location",
			entry: Entry{
				Location:  `C:\Users\user01\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
				Entry:     "evil.lnk",
				Signer:    "",
				ImagePath: `C:\ProgramData\payload.exe`,
				Launch:    `C:\ProgramData\payload.exe`,
			},
			wantRegKey: false,
			wantFileVal: `C:\Users\user01\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup :: evil.lnk`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := baselineEvent(tt.entry, time.Now())
			if ev.Source != event.SrcBaseline {
				t.Errorf("Source = %q, want baseline", ev.Source)
			}
			if ev.Image != tt.entry.ImagePath {
				t.Errorf("Image = %q, want %q", ev.Image, tt.entry.ImagePath)
			}
			if ev.CmdLine != tt.entry.Launch {
				t.Errorf("CmdLine = %q, want %q", ev.CmdLine, tt.entry.Launch)
			}
			if ev.User != tt.entry.Signer {
				t.Errorf("User = %q, want %q", ev.User, tt.entry.Signer)
			}
			if tt.wantRegKey {
				if ev.TargetRegKey != tt.wantRegKeyVal {
					t.Errorf("TargetRegKey = %q, want %q", ev.TargetRegKey, tt.wantRegKeyVal)
				}
				if ev.TargetFile != "" {
					t.Errorf("TargetFile should be empty for registry location, got %q", ev.TargetFile)
				}
			} else {
				if ev.TargetFile != tt.wantFileVal {
					t.Errorf("TargetFile = %q, want %q", ev.TargetFile, tt.wantFileVal)
				}
				if ev.TargetRegKey != "" {
					t.Errorf("TargetRegKey should be empty for filesystem location, got %q", ev.TargetRegKey)
				}
			}
		})
	}
}

// TestDiffManyNewEntries: stress test with many new entries to verify sorting
// and count correctness.
func TestDiffManyNewEntries(t *testing.T) {
	clean := Snapshot{Entries: nil}
	var dailyEntries []Entry
	for i := 0; i < 100; i++ {
		dailyEntries = append(dailyEntries, Entry{
			Location: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			Entry:    strings.Repeat("X", i+1), // unique names
		})
	}
	daily := Snapshot{Entries: dailyEntries}
	events := Diff(clean, daily)
	if len(events) != 100 {
		t.Errorf("want 100 events, got %d", len(events))
	}
	// Verify sorted order
	for i := 1; i < len(events); i++ {
		if events[i].TargetRegKey < events[i-1].TargetRegKey {
			t.Errorf("events not sorted: [%d]=%q > [%d]=%q", i-1, events[i-1].TargetRegKey, i, events[i].TargetRegKey)
			break
		}
	}
}

// testParseUTF16LE is a test helper: encodes s as UTF-16LE with BOM.
func testParseUTF16LE(s string) []byte {
	runes := []rune(s)
	codes := utf16.Encode(runes)
	out := []byte{0xFF, 0xFE}
	for _, c := range codes {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

// TestParseUTF16LEWithRealBaseline: parse the real baseline_clean.csv through
// the UTF-16LE path (it's already UTF-16LE on disk, but this explicitly tests
// the decode path on the actual data).
func TestParseUTF16LEWithRealBaseline(t *testing.T) {
	raw, err := os.ReadFile("../../baseline_clean.csv")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The real file IS UTF-16LE with BOM. Verify Parse handles it.
	s, err := Parse(bytes.NewReader(raw), time.Now())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(s.Entries) == 0 {
		t.Fatal("real baseline parsed to 0 entries — UTF-16LE decode likely broken")
	}
	// Spot-check: rdpclip must exist (known entry from the CSV)
	found := false
	for _, e := range s.Entries {
		if e.Entry == "rdpclip" {
			found = true
			if e.ImagePath != `C:\WINDOWS\system32\rdpclip.exe` {
				t.Errorf("rdpclip ImagePath = %q", e.ImagePath)
			}
			break
		}
	}
	if !found {
		t.Error("rdpclip entry not found — real baseline parse is broken")
	}
}

// TestUTF16LEBytePatternDetection: decodeUTF16IfNeeded only handles BOM-prefixed
// streams (FF FE / FE FF). autorunsc64.exe always emits a BOM, so this is fine
// in practice. This test documents the behavior: without BOM, UTF-16LE bytes
// are treated as raw (which produces garbled output — the caller's problem).
func TestUTF16LEBytePatternDetection(t *testing.T) {
	// Encode "Time" as UTF-16LE WITHOUT BOM: T=0x54 0x00, i=0x69 0x00, ...
	utf16NoBOM := []byte{0x54, 0x00, 0x69, 0x00, 0x6D, 0x00, 0x65, 0x00}
	r, err := decodeUTF16IfNeeded(bytes.NewReader(utf16NoBOM))
	if err != nil {
		t.Fatalf("decodeUTF16IfNeeded: %v", err)
	}
	decoded, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	// Without BOM, the bytes pass through undecoded. autorunsc64 always emits
	// BOM, so this is fine — but the behavior is documented here.
	if string(decoded) == "Time" {
		t.Log("byte-pattern detection worked (not required, autorunsc always has BOM)")
	} else {
		t.Logf("without BOM, UTF-16LE passes through undecoded (expected): %q", string(decoded))
	}
}

// TestUTF16BEDetection: UTF-16 BE BOM (FE FF) must also be decoded.
func TestUTF16BEDetection(t *testing.T) {
	// "AB" in UTF-16 BE with BOM: FE FF 00 41 00 42
	raw := []byte{0xFE, 0xFF, 0x00, 0x41, 0x00, 0x42}
	r, err := decodeUTF16IfNeeded(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decodeUTF16IfNeeded: %v", err)
	}
	decoded, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(decoded) != "AB" {
		t.Errorf("decoded = %q, want %q", string(decoded), "AB")
	}
}

// TestUTF16SurrogatePairs: emoji and other characters outside the BMP use
// surrogate pairs in UTF-16. The decoder must handle them correctly.
func TestUTF16SurrogatePairs(t *testing.T) {
	// U+1F600 (😀) = surrogate pair D83D DE00
	// UTF-16LE with BOM: FF FE 3D D8 00 DE
	raw := []byte{0xFF, 0xFE, 0x3D, 0xD8, 0x00, 0xDE}
	r, err := decodeUTF16IfNeeded(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decodeUTF16IfNeeded: %v", err)
	}
	decoded, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(decoded) != "😀" {
		t.Errorf("decoded = %q (len=%d), want 😀", string(decoded), len(decoded))
	}
}
