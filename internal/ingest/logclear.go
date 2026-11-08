package ingest

// Sysmon log-clear detection from the System log.
//
// Clearing an event log does NOT restart its RecordIds (measured 2026-11-07,
// Windows 11 26200: after `wevtutil cl Microsoft-Windows-Sysmon/Operational`
// the newest RecordId carried on from ~10.8M), so the ingester's rewind check
// never sees a clear. What every clear does leave is System log EID 104
// (provider Microsoft-Windows-Eventlog, "The <channel> log file was cleared"),
// which names the channel, the clearing user and the backup path. It cannot
// be raced by writing more events, and it survives a daemon restart, so a
// look-back window also reports clears that happened while Sentinel was down.

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"sentinel/internal/event"
	"sentinel/internal/sysmonxml"
)

const (
	// clearCheckInterval: the System-log query runs at start and then this
	// often, not on every read-loop pass.
	clearCheckInterval = 10 * time.Second

	// clearLookback is how far back the EID 104 query reaches. 24h covers a
	// daemon that was stopped overnight; TELEMETRY-002's 25h dedup (keyed on
	// Details, which carries the System RecordId) keeps a restart inside that
	// window from re-alerting a clear that was already reported.
	clearLookback = 24 * time.Hour
)

// logClear is one System EID 104 "log file was cleared" record.
type logClear struct {
	RecordID  uint64
	Time      time.Time
	Channel   string
	User      string // DOMAIN\user of the clearing account
	Backup    string // BackupPath ("" when cleared without a backup)
	ClientPID string
}

type logClearXML struct {
	RecordID    uint64 `xml:"System>EventRecordID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"System>TimeCreated"`
	Channel     string `xml:"UserData>LogFileCleared>Channel"`
	SubjectUser string `xml:"UserData>LogFileCleared>SubjectUserName"`
	SubjectDom  string `xml:"UserData>LogFileCleared>SubjectDomainName"`
	BackupPath  string `xml:"UserData>LogFileCleared>BackupPath"`
	ClientPID   string `xml:"UserData>LogFileCleared>ClientProcessId"`
}

// parseLogCleared decodes the rendered XML of a System EID 104 record.
func parseLogCleared(raw []byte) (logClear, error) {
	var x logClearXML
	if err := xml.Unmarshal(sysmonxml.SanitizeXML(raw), &x); err != nil {
		return logClear{}, fmt.Errorf("log-cleared xml: %w", err)
	}
	if x.Channel == "" {
		return logClear{}, fmt.Errorf("log-cleared xml: no Channel (record %d)", x.RecordID)
	}
	lc := logClear{
		RecordID:  x.RecordID,
		Channel:   strings.TrimSpace(x.Channel),
		Backup:    strings.TrimSpace(x.BackupPath),
		ClientPID: strings.TrimSpace(x.ClientPID),
	}
	if t, err := time.Parse(time.RFC3339Nano, x.TimeCreated.SystemTime); err == nil {
		lc.Time = t
	}
	if u := strings.TrimSpace(x.SubjectUser); u != "" {
		lc.User = u
		if d := strings.TrimSpace(x.SubjectDom); d != "" {
			lc.User = d + `\` + u
		}
	}
	return lc, nil
}

// clearKey identifies one EID 104 record. RecordId plus time, so the key stays
// unique even if the System log itself were cleared and its ids reused.
func (lc logClear) clearKey() string {
	return fmt.Sprintf("%d|%s", lc.RecordID, lc.Time.UTC().Format(time.RFC3339Nano))
}

// logClearedEvent is the synthetic event TELEMETRY-002 matches for a clear.
// Details starts with event.DetailsSysmonCleared and carries the System
// RecordId, so the rule's Details-based dedup key is unique per clear.
func logClearedEvent(lc logClear) event.Event {
	t := lc.Time
	if t.IsZero() {
		t = time.Now()
	}
	backup := lc.Backup
	if backup == "" {
		backup = "none"
	}
	return event.Event{
		Source: event.SrcSentinel,
		Time:   t,
		Image:  lc.Channel,
		User:   lc.User,
		Details: fmt.Sprintf("%s channel=%s cleared_at=%s by=%s client_pid=%s backup=%s system_record_id=%d",
			event.DetailsSysmonCleared, lc.Channel, t.Local().Format(time.RFC3339), lc.User, lc.ClientPID, backup, lc.RecordID),
	}
}

// clearTracker remembers which EID 104 records were already emitted in this
// run, so the look-back query (re-read every clearCheckInterval) emits each
// clear once. Restarts are covered by the rule's persisted dedup instead.
type clearTracker struct {
	seen map[string]time.Time // clearKey -> clear time
}

// fresh returns the clears of channel not emitted before and marks them seen.
// Entries older than the look-back (plus an hour) are pruned: the query can no
// longer return them.
func (ct *clearTracker) fresh(clears []logClear, channel string, now time.Time) []logClear {
	if ct.seen == nil {
		ct.seen = map[string]time.Time{}
	}
	for k, t := range ct.seen {
		if now.Sub(t) > clearLookback+time.Hour {
			delete(ct.seen, k)
		}
	}
	var out []logClear
	for _, lc := range clears {
		if !strings.EqualFold(lc.Channel, channel) {
			continue
		}
		k := lc.clearKey()
		if _, dup := ct.seen[k]; dup {
			continue
		}
		t := lc.Time
		if t.IsZero() {
			t = now
		}
		ct.seen[k] = t
		out = append(out, lc)
	}
	return out
}
