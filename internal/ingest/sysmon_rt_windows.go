//go:build windows

// Windows DEFAULT real-time Sysmon ingester: a PowerShell Get-WinEvent poller.
//
// Rationale: the native EvtSubscribe binding (sysmon_native_windows.go) fails
// with ERROR_INVALID_PARAMETER on a channel that Get-WinEvent reads cleanly from
// the same elevated process. Rather than block Phase 1 on debugging wevtapi
// marshalling, we shell out to powershell.exe Get-WinEvent — the exact cmdlet
// the operator already uses for IR, proven to read this channel.
//
// Flow:
//  1. Every `interval` (default 1s), run:
//     Get-WinEvent -FilterHashtable @{LogName=<ch>; ID=<eids>} -MaxEvents 2000
//     -ErrorAction SilentlyContinue
//     | Where-Object { $_.RecordId -gt <highWater> }
//     | ForEach-Object { base64(UTF16LE($_.ToXml())) }
//  2. For each base64 line: decode -> UTF-16LE bytes -> decodeUTF16LE -> sysmonxml.Parse.
//  3. Advance highWater to the max RecordId seen so the next poll is incremental.
//
// maxPerPoll (default 2000) must exceed the worst-case per-interval event count.
// Cursor peaks at ~100 events/sec, so 2000 covers ~20s of burst — well beyond
// the 1s poll interval. If a burst ever exceeds maxPerPoll, older events in the
// gap are skipped (rare, acceptable for a behavior engine).
//
// NOTE: -Oldest + StartTime was attempted to eliminate stranding entirely, but
// caused Get-WinEvent to exit with code 1 on sysmon 15.21/PS 5.1 (every poll
// after the first). Reverted to newest-first + large maxPerPoll.
//
// Trade-offs vs native EvtSubscribe (02-ARCHITECTURE.md §4.1 latency target):
//   - latency ~1-3s (powershell.exe spawn + parse) vs <1s native. Acceptable
//     for a behavior engine whose rules are not sub-second time-critical.
//   - one powershell.exe process per poll (cheap but not free). At 1s interval
//     that's ~60 proc-min/hour; negligible on this machine.
//
// The native binding stays available via `sentinel -sysmon-native` for when the
// EvtSubscribe bug is fixed.
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"

	"sentinel/internal/event"
	"sentinel/internal/pathnorm"
	"sentinel/internal/sysmonxml"
)

const (
	defaultPollInterval = 1 * time.Second
	// defaultMaxPerPoll caps the events fetched per Get-WinEvent call. Must be
	// large enough to absorb bursts (Cursor can generate hundreds of events per
	// second). At 1s poll interval, 2000 covers ~20s of peak burst — well beyond
	// the interval. If a burst ever exceeds this, older events in the gap are
	// skipped (rare, acceptable for a behavior engine).
	defaultMaxPerPoll = 2000
)

// defaultEIDs is the Sysmon EID set our rules use (03-RULES.md / 04-TELEMETRY §1).
// 16 (Sysmon config change) is included: it's the event that says "your
// telemetry rules just changed" — see rules.d/telemetry.yml TELEMETRY-001.
var defaultEIDs = []int{1, 3, 7, 8, 10, 11, 12, 13, 16, 19, 20, 21, 22, 23, 25}

// sysmonRT is the production (PowerShell poller) ingester.
type sysmonRT struct {
	channel    string
	eids       []int
	log        *slog.Logger
	interval   time.Duration
	maxPerPoll int
	// parents silences helper processes spawned by sentinel's own binaries
	// (poller/toast/eventlog powershell.exe, sentinel-tray's relay children).
	// Hash-gated (see selfParents) so an imposter dropped into our user-writable
	// install dir is detected rather than silenced.
	parents *selfParents
}

// NewSysmonRT constructs the default Sysmon ingester (PowerShell poller).
func NewSysmonRT(channel, _query string, log *slog.Logger) (Ingester, error) {
	// _query is accepted for API parity with the native constructor + the
	// -sysmon-query flag, but the poller filters EIDs server-side via
	// FilterHashtable instead of an XPath query, so it's intentionally unused.
	return &sysmonRT{
		channel:    channel,
		eids:       defaultEIDs,
		log:        log,
		interval:   defaultPollInterval,
		maxPerPoll: defaultMaxPerPoll,
		parents:    newSelfParents(),
	}, nil
}

// ownExeDir returns the directory of the running sentinel.exe (the install
// dir, where sentinel-tray.exe also lives), or "" if undeterminable.
func ownExeDir() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	// No EvalSymlinks: we match whatever path form Sysmon reports as ParentImage
	// (same NormalizePath on both stored and lookup side, as the old ownExePath
	// did), and os.Executable() already resolves the real path on Windows.
	// Resolving here but not on the lookup side would make a symlink-launched
	// binary fail to match (safe but noisy).
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

// Start implements Ingester.
func (s *sysmonRT) Start(ctx context.Context) (<-chan event.Event, error) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		return nil, fmt.Errorf("powershell.exe not on PATH: %w", err)
	}
	s.log.Info("sysmon RT (powershell poller) starting",
		"channel", s.channel, "eids", len(s.eids), "interval", s.interval,
		"maxPerPoll", s.maxPerPoll)
	out := make(chan event.Event, 4096)
	go s.pollLoop(ctx, out)
	return out, nil
}

func (s *sysmonRT) pollLoop(ctx context.Context, out chan<- event.Event) {
	defer close(out)
	// highWater tracks the max RecordId we've already emitted; -1 = emit the
	// most recent batch on first poll (good for smoke-test visibility), then go
	// forward incrementally.
	highWater := int64(-1)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	// one immediate poll so events appear without waiting a full interval
	s.pollAndEmit(ctx, &highWater, out)
	for {
		select {
		case <-ctx.Done():
			s.log.Info("sysmon RT poller stopping (context cancelled)")
			return
		case <-t.C:
			s.pollAndEmit(ctx, &highWater, out)
		}
	}
}

func (s *sysmonRT) pollAndEmit(ctx context.Context, highWater *int64, out chan<- event.Event) {
	events, newMax, err := s.poll(*highWater)
	if err != nil {
		s.log.Warn("poll failed", "err", err)
		return
	}
	// Saturation detection: if we got exactly maxPerPoll events, a burst exceeded
	// our fetch cap and some older events may have been skipped. This shouldn't
	// happen in steady state (2000 cap vs ~100 events/sec peak), but if it does,
	// the operator needs to know to investigate.
	if len(events) == s.maxPerPoll {
		s.log.Warn("sysmon poll saturated at maxPerPoll cap; events may be delayed",
			"fetched", len(events), "maxPerPoll", s.maxPerPoll)
	}
	if newMax > *highWater {
		*highWater = newMax
	}
	for _, ev := range events {
		// Self-ingestion filter (see isSelfChild).
		if s.isSelfChild(ev) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case out <- ev:
		}
	}
}

// isSelfChild reports whether ev is a process spawned by a sentinel binary
// (sentinel.exe / sentinel-tray.exe) whose on-disk hash still matches startup
// — the poller's powershell.exe child (every poll), the toast/eventlog
// alerters' powershell.exe children (every alert), the tray relay's children.
// Together ~1 EID 1/sec of self-noise. Hash-gating means an imposter swapped
// into our user-writable install dir is NOT silenced (detected instead).
// ParentImage is only meaningful for EID 1, so we gate on EID.
func (s *sysmonRT) isSelfChild(ev event.Event) bool {
	return ev.EID == 1 && s.parents.matches(ev.ParentImage, time.Now())
}

// poll runs one Get-WinEvent query and returns the parsed new events (RecordId
// > afterID) plus the max RecordId observed (for the next call's afterID).
//
// NOTE: we intentionally do NOT use -Oldest or StartTime here. Testing on
// sysmon 15.21 / PowerShell 5.1 showed Get-WinEvent -FilterHashtable with
// StartTime + -Oldest exits with code 1 (empty stderr, suppressed by
// SilentlyContinue) on every poll after the first, breaking ingestion entirely.
// The newest-first default + a large maxPerPoll (2000) handles bursts safely:
// Cursor peaks at ~100 events/sec, so 2000 covers ~20s of burst — well beyond
// the 1s poll interval. Rare stranding under extreme load is acceptable for a
// behavior engine; total ingestion failure is not.
func (s *sysmonRT) poll(afterID int64) ([]event.Event, int64, error) {
	script := fmt.Sprintf(
		`$ErrorActionPreference='SilentlyContinue'; `+
			`Get-WinEvent -FilterHashtable @{LogName='%s'; ID=%s} -MaxEvents %d | `+
			`Where-Object { $_.RecordId -gt %d } | `+
			`ForEach-Object { try { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($_.ToXml())) } catch {} }`,
		s.channel, eidList(s.eids), s.maxPerPoll, afterID,
	)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// CREATE_NO_WINDOW (0x08000000): when launched by Task Scheduler there is no
	// inherited console, so Windows would allocate a fresh one for powershell.exe
	// each poll cycle — flashing a window on the desktop every 1-3s (annoying +
	// an OPSEC tell). This allocates NO console instead of a hidden one, which is
	// the correct semantic for a headless child with captured stdout/stderr.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	runErr := cmd.Run()

	var events []event.Event
	var maxID int64
	for _, line := range strings.Split(stdout.String(), "\n") {
		line := strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Per-line recover: a panic in base64 decode, UTF-16 decode, or
		// sysmonxml.Parse on an attacker-shaped event value must skip ONE
		// event, not kill the poller goroutine (and with it the SYSTEM daemon
		// = detection blinded). Mirrors dispatcher.go's callAlerter recover.
		var (
			xmlUTF16 []byte
			xmlStr   string
			ev       event.Event
			err      error
		)
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Warn("parse panic contained; event skipped",
						"record_id", ev.RecordID, "panic", r)
					err = fmt.Errorf("panic: %v", r)
				}
			}()
			xmlUTF16, err = base64.StdEncoding.DecodeString(line)
			if err != nil {
				s.log.Debug("base64 decode skipped", "err", err)
				return
			}
			xmlStr, err = decodeUTF16LE(xmlUTF16)
			if err != nil {
				s.log.Debug("utf16 decode skipped", "err", err)
				return
			}
			ev, err = sysmonxml.Parse([]byte(xmlStr), event.SrcSysmonRT)
		}()
		if err != nil {
			continue
		}
		if int64(ev.RecordID) > maxID {
			maxID = int64(ev.RecordID)
		}
		events = append(events, ev)
	}
	// PowerShell exit codes are unreliable for our purposes. Two things can set
	// a nonzero exit: (1) Get-WinEvent's non-terminating "No events found"
	// error, which SilentlyContinue suppresses (and which doesn't actually set a
	// nonzero exit on its own in PS 5.1), and (2) a TERMINATING error from a .NET
	// method call inside the pipeline — specifically $_.ToXml() throwing on a
	// malformed event record. SilentlyContinue does NOT stop terminating errors,
	// so one bad event aborts the entire ForEach-Object and powershell.exe exits
	// code 1. The try/catch in the script (above) catches that, but we keep this
	// Go-side guard as a belt-and-suspenders: if stdout nonetheless has valid
	// base64 lines we already parsed them — discarding data over an exit code
	// would blind ingestion. Only treat the nonzero exit as real when we got
	// nothing usable out of it.
	if runErr != nil && len(events) == 0 {
		// Genuinely broken: nonzero exit AND no usable output. Include raw
		// stdout byte/line count so we can distinguish "powershell produced
		// nothing" (pipe/cmdlet failure) from "produced lines we couldn't
		// parse" (XML/base64 failure on specific events).
		rawLines := len(strings.Split(strings.TrimSpace(stdout.String()), "\n"))
		return nil, 0, fmt.Errorf("powershell: %w (stderr: %s; stdout %d bytes/%d lines)",
			runErr, strings.TrimSpace(stderr.String()), stdout.Len(), rawLines)
	}
	if runErr != nil {
		// nonzero exit but we still got events: a suppressed non-fatal error
		// (the common PowerShell gotcha). Log at debug, keep the data.
		s.log.Debug("powershell exited nonzero but produced output; ignoring exit code",
			"exit_err", runErr, "events", len(events))
	}
	return events, maxID, nil
}

// eidList renders the EID slice as a PowerShell array literal "1,3,7,...".
func eidList(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ",")
}

// decodeUTF16LE converts little-endian UTF-16 bytes to a Go string. Shared with
// the experimental native ingester (sysmon_native_windows.go).
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

// defaultEIDQuery is retained for the experimental native ingester's XPath query.
func defaultEIDQuery() string {
	var ors string
	for i, id := range defaultEIDs {
		if i > 0 {
			ors += " or "
		}
		ors += fmt.Sprintf("EventID=%d", id)
	}
	return fmt.Sprintf("*[System[%s]]", ors)
}
