//go:build windows

// Helpers for the Sysmon ingester (sysmon_rt_windows.go): the subscribed EID
// set, the hash-gated self-ingestion filter, drop accounting, XML decoding and
// the RecordId rewind check.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf16"

	"sentinel/internal/event"
	"sentinel/internal/pathnorm"
	"sentinel/internal/sysmonxml"
)

// defaultEIDs is the Sysmon EID set our rules use (03-RULES.md / 04-TELEMETRY §1).
// 16 (Sysmon config change) is included: it's the event that says "your
// telemetry rules just changed" — see rules.d/telemetry.yml TELEMETRY-001.
var defaultEIDs = []int{1, 3, 7, 8, 10, 11, 12, 13, 16, 19, 20, 21, 22, 23, 25}

// defaultEIDQuery is the subscription's XPath query for defaultEIDs.
func defaultEIDQuery() string {
	var ors string
	for i, id := range defaultEIDs {
		if i > 0 {
			ors += " or "
		}
		ors += fmt.Sprintf("EventID=%d", id)
	}
	return fmt.Sprintf("*[System[(%s)]]", ors)
}

// ownExeDir returns the directory of the running sentinel.exe (the install
// dir, where sentinel-tray.exe also lives), or "" if undeterminable.
func ownExeDir() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	// No EvalSymlinks: we match whatever path form Sysmon reports as ParentImage
	// (same NormalizePath on both stored and lookup side), and os.Executable()
	// already resolves the real path on Windows. Resolving here but not on the
	// lookup side would make a symlink-launched binary fail to match (safe but
	// noisy).
	return filepath.Dir(p)
}

// selfRecheck bounds how often a self-parent binary is re-hashed: at most one
// SHA256 of sentinel.exe / sentinel-tray.exe per path per window. Large enough
// that verify cost is negligible under toast bursts (~12ms for a 6MB binary,
// once per 5s); small enough that a post-startup binary swap is caught soon.
// A swapped-but-cached binary leaves a blind window up to selfRecheck wide —
// acceptable given the foothold needed (write our dir + replace a running exe +
// time the spawn inside the window).
const selfRecheck = 5 * time.Second

// selfParents maps the normalized paths of sentinel's own binaries to the
// SHA256 recorded at startup. A process whose ParentImage matches one is
// silenced ONLY if the on-disk binary still hashes to the recorded value, so a
// same-named imposter swapped into our (user-writable) install dir is detected
// instead of given a free pass to spawn -ep bypass powershell. Verification is
// cached per path for selfRecheck to bound cost; a verify failure (missing /
// changed / unreadable) returns false = the event is NOT silenced (fail-open
// for detection). A nil or empty selfParents disables filtering (safe, noisier).
type selfParents struct {
	want map[string]string // normalized parent path -> lowercase hex SHA256
	mu   sync.Mutex
	ok   map[string]time.Time // normalized parent path -> last successful verify
}

// newSelfParents hashes sentinel.exe and sentinel-tray.exe in the install dir.
// An unreadable or unbuilt sibling is skipped (not added) so its children are
// detected rather than silenced — safe.
func newSelfParents() *selfParents {
	sp := &selfParents{want: map[string]string{}, ok: map[string]time.Time{}}
	dir := ownExeDir()
	if dir == "" {
		return sp
	}
	for _, name := range []string{"sentinel.exe", "sentinel-tray.exe"} {
		p := pathnorm.NormalizePath(filepath.Join(dir, name))
		if h, err := sha256of(p); err == nil {
			sp.want[p] = h
		}
	}
	return sp
}

// matches reports whether parentImage is a sentinel-binary whose on-disk hash
// still matches startup. now is injected so tests control the cache clock.
func (sp *selfParents) matches(parentImage string, now time.Time) bool {
	if sp == nil || len(sp.want) == 0 || parentImage == "" {
		return false
	}
	p := pathnorm.NormalizePath(parentImage)
	want, ok := sp.want[p]
	if !ok {
		return false
	}
	sp.mu.Lock()
	last, seen := sp.ok[p]
	sp.mu.Unlock()
	if seen && now.Sub(last) < selfRecheck {
		return true // recently confirmed legit; trust until recheck expires
	}
	h, err := sha256of(p)
	if err != nil || h != want {
		return false // imposter / swapped / unreadable -> do NOT silence
	}
	sp.mu.Lock()
	sp.ok[p] = now
	sp.mu.Unlock()
	return true
}

// isSelfChild reports whether ev is a process spawned by a sentinel binary
// (sentinel.exe / sentinel-tray.exe) whose on-disk hash still matches startup
// — the toast/eventlog alerters' powershell.exe children (every alert) and the
// tray relay's children. Hash-gating means an imposter swapped into our
// user-writable install dir is NOT silenced (detected instead). ParentImage is
// only meaningful for EID 1, so we gate on EID.
func (sp *selfParents) isSelfChild(ev event.Event) bool {
	return ev.EID == 1 && sp.matches(ev.ParentImage, time.Now())
}

// sha256of returns the lowercase hex SHA256 of the file at path.
func sha256of(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// dropWarnEvery bounds the "event dropped" WARN to one line per window (with
// the running total), so a flood of malformed records cannot flood the log.
const dropWarnEvery = time.Minute

// dropCounter counts events the ingester received but could not render or
// parse. Each one is an event no rule saw, so it is surfaced at WARN (rate
// limited by dropWarnEvery) instead of being skipped silently. Used only from
// the single read goroutine (no locking).
type dropCounter struct {
	dropped      uint64
	lastDropWarn time.Time
}

// note records one undecodable event and logs at WARN at most once per
// dropWarnEvery.
func (d *dropCounter) note(log *slog.Logger, err error) {
	d.dropped++
	now := time.Now()
	if now.Sub(d.lastDropWarn) < dropWarnEvery {
		return
	}
	d.lastDropWarn = now
	log.Warn("sysmon event dropped: could not decode/parse (no rule saw it)",
		"err", err, "dropped_total", d.dropped)
}

// parseRenderedXML turns one event's UTF-16LE XML (EvtRender output) into an
// event. A panic in UTF-16 decode or sysmonxml.Parse on an attacker-shaped
// event value must skip ONE event, not kill the read goroutine (and with it
// the SYSTEM daemon = detection blinded), so it is recovered and returned as
// an error. Mirrors dispatcher.go's callAlerter recover.
func parseRenderedXML(log *slog.Logger, xmlUTF16 []byte) (ev event.Event, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Warn("parse panic contained; event skipped", "panic", r)
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	xmlStr, err := decodeUTF16LE(xmlUTF16)
	if err != nil {
		return event.Event{}, err
	}
	return sysmonxml.Parse([]byte(xmlStr), event.SrcSysmonRT)
}

// decodeUTF16LE converts little-endian UTF-16 bytes to a Go string.
func decodeUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("odd-length UTF-16 (%d bytes)", len(b))
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u)), nil
}

// recordIDsRewound reports whether a RecordId is below the high-water already
// consumed — the signature of a recreated channel (RecordIds restart at 1).
// Negative values (nothing seen / nothing consumed yet) are never a rewind.
func recordIDsRewound(id, highWater int64) bool {
	return id >= 0 && highWater >= 0 && id < highWater
}

// rewoundEvent is the synthetic event TELEMETRY-002 matches. Image carries the
// channel name so alerts and dedup keys say what was rewound; the numbers go
// in Details for the operator.
func rewoundEvent(channel string, id, highWater int64) event.Event {
	return event.Event{
		Source:  event.SrcSentinel,
		Time:    time.Now(),
		Image:   channel,
		Details: fmt.Sprintf("%s channel=%s newest_record_id=%d previous_high_water=%d", event.DetailsSysmonRewound, channel, id, highWater),
	}
}
