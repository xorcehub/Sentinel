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
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sentinel/internal/event"
)

type sysmonEvent struct {
	XMLName    xml.Name     `xml:"Event"`
	EventID    int          `xml:"System>EventID"`
	RecordID   uint64       `xml:"System>EventRecordID"`
	TimeCreated timeCreated `xml:"System>TimeCreated"`
	Computer   string       `xml:"System>Computer"`
	Data       []dataItem   `xml:"EventData>Data"`
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
	if err := xml.Unmarshal(raw, &se); err != nil {
		return event.Event{}, fmt.Errorf("sysmonxml parse: %w", err)
	}
	m := make(map[string]string, len(se.Data))
	for _, d := range se.Data {
		if d.Name != "" {
			m[d.Name] = strings.TrimSpace(d.Value)
		}
	}

	ev := event.Event{
		Source:   src,
		RecordID: se.RecordID,
		EID:      se.EventID,
		Time:     parseTime(se.TimeCreated.SystemTime, m["UtcTime"]),
		Image:    m["Image"],
		CmdLine:  m["CommandLine"],
		ParentImage:   m["ParentImage"],
		ParentCmdLine: m["ParentCommandLine"],
		User:     m["User"],

		ImageLoaded: m["ImageLoaded"],
		Signed:      m["Signed"],
		Signature:   m["Signature"],

		SourceImage:   m["SourceImage"],
		TargetImage:   m["TargetImage"],
		GrantedAccess: m["GrantedAccess"],

		DstIP:    m["DestinationIp"],
		DstProto: m["Protocol"],
		TargetFile:   m["TargetFilename"],
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
