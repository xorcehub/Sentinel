// Package baseline implements Sentinel's persistence-surface diff (Phase 3,
// 06-BASELINE.md). It captures autorunsc64.exe output (CSV), and diffs a daily
// capture against a signed-off clean baseline, emitting pseudo-events for every
// NEW entry. This catches the RESULT of persistence even when the act was
// missed by the behavior rules (e.g. a quiet installer that wrote a Run-key
// with no LOLBin, no network).
//
// Source: Sysinternals autorunsc64.exe, invoked as
//
//	autorunsc64.exe -accepteula -nobanner -a * -c -s -t
//
// Flags: -a * = all locations; -c = CSV to stdout; -s = verify signatures
// (populates Signer); -t = normalized UTC timestamps (stable for diffing).
// Hashes (-h) are deliberately NOT enabled - they churn on every legit update.
//
// Coverage: 262 autorun locations vs the ~7 my custom collectors would have
// covered. Maintained by Sysinternals. See the Phase 3 design pivot (06 §8).
package baseline

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"io"
	"strings"
	"time"
	"unicode/utf16"
)

// Entry is one autorun row. The CSV schema (autorunsc64 -c -s -t) is:
//
//	Time, Entry Location, Entry, Enabled, Category, Profile, Description,
//	Signer, Company, Image Path, Version, Launch String
//
// Field names here are Go-idiomatic; the CSV header is mapped in Parse. Not all
// fields are used for the diff - see Key().
type Entry struct {
	Time        string // normalized UTC (YYYYMMDD-hhmmss); display only, not a diff key
	Location    string // Entry Location - the persistence surface (registry path / folder / svc key)
	Entry       string // the entry name (e.g. "Discord", "SecurityHealth")
	Enabled     string // "enabled"/"disabled"/"" - kept, not diffed
	Category    string // "Logon"/"Services"/"Drivers"/... - triage grouping
	Profile     string // "System-wide"/"user01" - whose context
	Description string // human description
	Signer      string // "(Verified) Microsoft Windows" etc. - from -s
	Company     string // signer company name
	ImagePath   string // executable path
	Version     string // file version
	Launch      string // the launch command (registry data / cmdline)
}

// Key is the stable identity used by the diff: Location + Entry. A Discord
// update (new Time/Signer/Version) keeps the same Key, so it does NOT generate
// a diff event. Only genuinely new (Location,Entry) pairs fire. This is the
// core churn-suppression decision.
func (e Entry) Key() string { return e.Location + "\x00" + e.Entry }

// Snapshot is a point-in-time capture of all autorun entries. Entries is the
// only data; TakenAt lets diffs age results and supports file naming.
type Snapshot struct {
	TakenAt time.Time
	Entries []Entry
}

// Parse reads autorunsc64 CSV output (one snapshot) from r. Rows whose Entry
// field is empty are section headers (e.g. an empty RunOnce key) and are
// skipped - they're structural, not real persistence entries, and diffing them
// would fire on every location that flips empty<->populated. Returns the
// parsed snapshot plus any read error.
func Parse(r io.Reader, takenAt time.Time) (Snapshot, error) {
	// autorunsc64.exe emits UTF-16 LE (BOM FF FE) on Windows - like most legacy
	// CLI tools. encoding/csv is UTF-8-only and would see 'T\x00i\x00m\x00e\x00'
	// as the header, match nothing in indexMap, and silently return zero entries.
	// (This was the live on-host bug: --baseline-now reported clean=0, daily=0.)
	// Sniff the BOM/byte pattern and decode UTF-16LE -> UTF-8 first.
	decoded, err := decodeUTF16IfNeeded(r)
	if err != nil {
		return Snapshot{}, err
	}
	cr := csv.NewReader(decoded)
	cr.FieldsPerRecord = -1 // tolerate schema growth (autorunsc may add columns)
	// LazyQuotes=true tolerates autorunsc's non-RFC-compliant CSV: it emits bare
	// " characters inside UNQUOTED fields (e.g. the Signer field '(Not verified)
	// (Not Verified) Igor Pavlov' on unsigned 7-Zip entries). Strict RFC 4180
	// rejects this with 'bare " in non-quoted-field'; LazyQuotes accepts it.
	// Requires Go 1.23+ (go.mod pins 1.26). This is the documented fix for
	// parsing loose real-world CSV like autorunsc/Excel exports.
	cr.LazyQuotes = true
	cr.ReuseRecord = false

	header, err := cr.Read()
	if err != nil {
		return Snapshot{}, err
	}
	idx := indexMap(header)

	var entries []Entry
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Snapshot{}, err
		}
		// Skip section-header rows: real entries always have an Entry name.
		// (autorunsc emits a row per location even when empty, mirroring the
		// [location] headers in the .txt format.)
		entryName := field(rec, idx, "Entry")
		if strings.TrimSpace(entryName) == "" {
			continue
		}
		entries = append(entries, Entry{
			Time:        field(rec, idx, "Time"),
			Location:    field(rec, idx, "Entry Location"),
			Entry:       entryName,
			Enabled:     field(rec, idx, "Enabled"),
			Category:    field(rec, idx, "Category"),
			Profile:     field(rec, idx, "Profile"),
			Description: field(rec, idx, "Description"),
			Signer:      field(rec, idx, "Signer"),
			Company:     field(rec, idx, "Company"),
			ImagePath:   field(rec, idx, "Image Path"),
			Version:     field(rec, idx, "Version"),
			Launch:      field(rec, idx, "Launch String"),
		})
	}
	return Snapshot{TakenAt: takenAt, Entries: entries}, nil
}

// indexMap maps CSV header names to column indices, case-insensitively. We look
// up by name (not position) so a future autorunsc version adding/removing a
// column doesn't silently shift our field reads.
func indexMap(header []string) map[string]int {
	m := make(map[string]int, len(header))
	for i, h := range header {
		m[strings.ToLower(strings.TrimSpace(h))] = i
	}
	return m
}

func field(rec []string, idx map[string]int, name string) string {
	i, ok := idx[strings.ToLower(name)]
	if !ok || i < 0 || i >= len(rec) {
		return ""
	}
	return rec[i]
}

// decodeUTF16IfNeeded returns r unchanged for UTF-8/ASCII input, or a reader of
// the UTF-16LE-decoded UTF-8 bytes if the input carries a UTF-16 BOM (FF FE)
// or shows the UTF-16LE byte pattern (ASCII char followed by 0x00). autorunsc64
// emits UTF-16LE; without this decode, csv parsing silently yields zero entries
// because the header 'T\x00i\x00m\x00e\x00' matches no expected column name.

// decodeUTF16IfNeeded returns a reader of UTF-8 bytes. autorunsc64.exe emits
// UTF-16 LE (BOM FF FE) on Windows; encoding/csv is UTF-8-only and would
// otherwise see 'T\x00i\x00m\x00e\x00' as the header, match no expected
// column, and silently yield zero entries. (This was the live on-host bug:
// --baseline-now reported clean=0, daily=0.) BOM-sniff -> decode.
//
// Read-all + decode is correct and simple for baseline snapshots (~1MB); the
// streaming version was buggy on surrogate pairs and not worth the complexity.
func decodeUTF16IfNeeded(r io.Reader) (io.Reader, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(raw) >= 2 {
		if raw[0] == 0xFF && raw[1] == 0xFE {
			return bytes.NewReader(utf16ToUTF8(raw[2:], binary.LittleEndian)), nil
		}
		if raw[0] == 0xFE && raw[1] == 0xFF {
			return bytes.NewReader(utf16ToUTF8(raw[2:], binary.BigEndian)), nil
		}
	}
	return bytes.NewReader(raw), nil
}

// utf16ToUTF8 decodes a UTF-16 code-unit byte stream (endian per order) to UTF-8.
func utf16ToUTF8(b []byte, order binary.ByteOrder) []byte {
	if len(b)%2 != 0 {
		// Trailing odd byte: drop it (malformed input, not worth erroring on).
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = order.Uint16(b[2*i : 2*i+2])
	}
	return []byte(string(utf16.Decode(u)))
}
