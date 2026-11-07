// Package sysmonxml parses Sysmon event XML (as rendered by EvtRender from the
// Microsoft-Windows-Sysmon/Operational log) into a normalized event.Event.
//
// Tolerant by design: unknown <Data Name="..."> entries are ignored, missing
// entries yield zero values. This is the only place that maps raw Sysmon XML
// to struct fields — paired with event.Event.Field() (the Sigma-name→field
// map), the EID-7/EID-10 "wrong field" bug class is closed from both ends.
//
// XML namespace note: Sysmon's root carries a default xmlns. Go's encoding/xml
// matches elements by local name when struct tags carry no namespace prefix,
// so the tags below (EventID, EventRecordID, Data, ...) match regardless. The
// fixture in the test uses the real namespace to confirm this on the host.
package sysmonxml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"sentinel/internal/event"
)

type sysmonEvent struct {
	XMLName     xml.Name    `xml:"Event"`
	EventID     int         `xml:"System>EventID"`
	RecordID    uint64      `xml:"System>EventRecordID"`
	TimeCreated timeCreated `xml:"System>TimeCreated"`
	Computer    string      `xml:"System>Computer"`
	Data        []dataItem  `xml:"EventData>Data"`
}

type timeCreated struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type dataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// Parse converts one Sysmon event XML document into an Event. `src` tags the
// resulting Event.Source (rt / sweep / etc.) — the XML carries no such notion.
func Parse(raw []byte, src event.Source) (event.Event, error) {
	var se sysmonEvent
	if err := xml.Unmarshal(SanitizeXML(raw), &se); err != nil {
		return event.Event{}, fmt.Errorf("sysmonxml parse: %w", err)
	}
	m := make(map[string]string, len(se.Data))
	for _, d := range se.Data {
		if d.Name != "" {
			m[d.Name] = strings.TrimSpace(d.Value)
		}
	}

	ev := event.Event{
		Source:        src,
		RecordID:      se.RecordID,
		EID:           se.EventID,
		Time:          parseTime(se.TimeCreated.SystemTime, m["UtcTime"]),
		Image:         m["Image"],
		CmdLine:       m["CommandLine"],
		ParentImage:   m["ParentImage"],
		ParentCmdLine: m["ParentCommandLine"],
		User:          m["User"],

		ImageLoaded: m["ImageLoaded"],
		Signed:      m["Signed"],
		Signature:   m["Signature"],

		SourceImage:   m["SourceImage"],
		TargetImage:   m["TargetImage"],
		GrantedAccess: m["GrantedAccess"],
		// EID 8/10 PIDs + EID 8 thread start address. TargetImage is often
		// Sysmon's literal "<unknown process>" (victim exited before the event
		// was written) — these four are what's left of the victim then.
		SourcePID:     m["SourceProcessId"],
		TargetPID:     m["TargetProcessId"],
		StartModule:   m["StartModule"],
		StartFunction: m["StartFunction"],

		DstIP:        m["DestinationIp"],
		DstProto:     m["Protocol"],
		TargetFile:   m["TargetFilename"],
		Archived:     m["Archived"],
		TargetRegKey: m["TargetObject"],
		Details:      m["Details"],

		QueryName:    m["QueryName"],
		QueryResults: m["QueryResults"],
	}
	if p, err := strconv.Atoi(m["DestinationPort"]); err == nil {
		ev.DstPort = p
	}
	ev.Hashes = parseHashes(m["Hashes"])
	return ev, nil
}

// SanitizeXML replaces everything encoding/xml would reject as a character
// with U+FFFD, so one bad character can no longer discard a whole event:
//
//   - raw characters outside the XML 1.0 Char production (C0 controls other
//     than tab/LF/CR, U+FFFE, U+FFFF) and invalid UTF-8 bytes;
//   - numeric character references to such characters (&#x1; / &#1;).
//
// Why: a process can put e.g. U+0001 in its own command line. encoding/xml
// fails the entire document on it ("illegal character code U+0001"), so the
// event was dropped before any rule saw it — a one-byte detection bypass.
// U+FFFD (not deletion) keeps the tampering visible in alerts and never glues
// neighbouring tokens together into a new spelling. Everything else, including
// valid character references and entity references, is left byte-identical.
// Returns raw itself when nothing needs replacing (the common case).
func SanitizeXML(raw []byte) []byte {
	if !needsSanitize(raw) {
		return raw
	}
	out := make([]byte, 0, len(raw)+16)
	for i := 0; i < len(raw); {
		if raw[i] == '&' && i+2 < len(raw) && raw[i+1] == '#' {
			if n, cp, ok := parseCharRef(raw[i:]); ok {
				if isXMLChar(cp) {
					out = append(out, raw[i:i+n]...)
				} else {
					out = append(out, "&#xFFFD;"...)
				}
				i += n
				continue
			}
		}
		r, size := utf8.DecodeRune(raw[i:])
		if (r == utf8.RuneError && size <= 1) || !isXMLChar(r) {
			out = utf8.AppendRune(out, utf8.RuneError)
		} else {
			out = append(out, raw[i:i+size]...)
		}
		i += size
	}
	return out
}

// needsSanitize is the allocation-free fast path: true when raw contains
// invalid UTF-8, a raw non-XML character, or a numeric character reference
// (which must be inspected).
func needsSanitize(raw []byte) bool {
	if !utf8.Valid(raw) {
		return true
	}
	for i := 0; i < len(raw); {
		c := raw[i]
		if c < utf8.RuneSelf {
			if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
				return true
			}
			if c == '&' && i+1 < len(raw) && raw[i+1] == '#' {
				return true
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(raw[i:])
		if !isXMLChar(r) {
			return true
		}
		i += size
	}
	return false
}

// parseCharRef parses a numeric character reference at the start of b
// ("&#x1F;" or "&#31;"). Returns its byte length and code point; ok=false when
// b does not start with a well-formed reference (left for encoding/xml to judge).
func parseCharRef(b []byte) (n int, cp rune, ok bool) {
	end := bytes.IndexByte(b, ';')
	if end < 3 || end > 12 { // "&#" + 1..10 digits/x+hex + ";"
		return 0, 0, false
	}
	body := string(b[2:end])
	base := 10
	if body[0] == 'x' {
		base, body = 16, body[1:]
	}
	if body == "" {
		return 0, 0, false
	}
	v, err := strconv.ParseUint(body, base, 32)
	if err != nil {
		return 0, 0, false
	}
	if v > utf8.MaxRune {
		v = 0 // out of range: treat as illegal so it is replaced
	}
	return end + 1, rune(v), true
}

// isXMLChar reports whether r is in the XML 1.0 Char production.
func isXMLChar(r rune) bool {
	return r == 0x09 || r == 0x0A || r == 0x0D ||
		(r >= 0x20 && r <= 0xD7FF) ||
		(r >= 0xE000 && r <= 0xFFFD) ||
		(r >= 0x10000 && r <= utf8.MaxRune)
}

// parseTime prefers the SystemTime attr (RFC3339-ish), falls back to Sysmon's
// UtcTime ("2026-06-26 14:03:11.000"), then to now(). Never returns an error.
func parseTime(systemTime, utcTime string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.0000000Z"} {
		if systemTime != "" {
			if t, err := time.Parse(layout, systemTime); err == nil {
				return t
			}
		}
	}
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05"} {
		if utcTime != "" {
			if t, err := time.Parse(layout, utcTime); err == nil {
				return t
			}
		}
	}
	return time.Now()
}

// parseHashes turns "SHA256=abc,IMPHASH=def" into a map.
func parseHashes(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
