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
//       Get-WinEvent -FilterHashtable @{LogName=<ch>; ID=<eids>} -MaxEvents N
//         -ErrorAction SilentlyContinue
//       | Where-Object { $_.RecordId -gt <highWater> }
//       | ForEach-Object { base64(UTF16LE($_.ToXml())) }
//  2. For each base64 line: decode -> UTF-16LE bytes -> decodeUTF16LE -> sysmonxml.Parse.
//  3. Advance highWater to the max RecordId seen so the next poll is incremental.
//
// Trade-offs vs native EvtSubscribe (02-ARCHITECTURE.md §4.1 latency target):
//   - latency ~1-3s (powershell.exe spawn + parse) vs <1s native. Acceptable
//     for a behavior engine whose rules are not sub-second time-critical.
//   - one powershell.exe process per poll (cheap but not free). At 1s interval
//     that's ~60 proc-min/hour; negligible on this machine.
//   - under extreme burst (>maxPerPoll events between polls) the oldest
//     un-fetched events are skipped. Raised by increasing maxPerPoll.
//
// The native binding stays available via `sentinel -sysmon-native` for when the
// EvtSubscribe bug is fixed.
package ingest

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"sentinel/internal/event"
	"sentinel/internal/pathnorm"
	"sentinel/internal/sysmonxml"
)

const (
	defaultPollInterval = 1 * time.Second
	defaultMaxPerPoll   = 200
)

// defaultEIDs is the Sysmon EID set our rules use (03-RULES.md / 04-TELEMETRY §1).
var defaultEIDs = []int{1, 3, 7, 8, 10, 11, 12, 13, 19, 20, 21, 22, 23, 25}

// sysmonRT is the production (PowerShell poller) ingester.
type sysmonRT struct {
	channel    string
	eids       []int
	log        *slog.Logger
	interval   time.Duration
	maxPerPoll int
	// selfExe is the normalized path of sentinel.exe itself. Events whose
	// ParentImage matches are skipped: the poller's powershell.exe child and the
	// toast/eventlog alerters' powershell.exe children are all spawned by
	// sentinel.exe, and ingesting them floods the log + buries real activity at
	// ~1 EID 1/sec. An attacker cannot make sentinel.exe their parent without
	// already controlling the process, so this filter has no false-negative risk.
	selfExe string
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
		selfExe:    ownExePath(),
	}, nil
}

// ownExePath returns the normalized absolute path of the running sentinel.exe,
	// or "" if it can't be determined (in which case self-ingestion filtering is
// disabled — safe, just noisier). Normalized via pathnorm so it matches Sysmon's
// reported ParentImage regardless of slash/case form.
func ownExePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return pathnorm.NormalizePath(p)
}

// Start implements Ingester.
func (s *sysmonRT) Start(ctx context.Context) (<-chan event.Event, error) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		return nil, fmt.Errorf("powershell.exe not on PATH: %w", err)
	}
	s.log.Info("sysmon RT (powershell poller) starting",
		"channel", s.channel, "eids", len(s.eids), "interval", s.interval)
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

// isSelfChild reports whether ev is a process spawned by sentinel.exe itself —
// the poller's powershell.exe child (every poll cycle) and the toast/eventlog
// alerters' powershell.exe children (every alert). Together ~1 EID 1/sec of
// self-noise that buries real activity. An attacker cannot make sentinel.exe
// their parent without already controlling the process, so no false-negative
// risk. ParentImage is only meaningful for EID 1, so we gate on EID.
func (s *sysmonRT) isSelfChild(ev event.Event) bool {
	return ev.EID == 1 && s.selfExe != "" && pathnorm.NormalizePath(ev.ParentImage) == s.selfExe
}

// poll runs one Get-WinEvent query and returns the parsed new events (RecordId
// > afterID) plus the max RecordId observed (for the next call's afterID).
func (s *sysmonRT) poll(afterID int64) ([]event.Event, int64, error) {
	script := fmt.Sprintf(
		`$ErrorActionPreference='SilentlyContinue'; `+
			`Get-WinEvent -FilterHashtable @{LogName='%s'; ID=%s} -MaxEvents %d | `+
			`Where-Object { $_.RecordId -gt %d } | `+
			`ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($_.ToXml())) }`,
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
	if err := cmd.Run(); err != nil {
		return nil, 0, fmt.Errorf("powershell: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	var events []event.Event
	var maxID int64
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		xmlUTF16, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			s.log.Debug("base64 decode skipped", "err", err)
			continue
		}
		xmlStr, err := decodeUTF16LE(xmlUTF16)
		if err != nil {
			s.log.Debug("utf16 decode skipped", "err", err)
			continue
		}
		ev, err := sysmonxml.Parse([]byte(xmlStr), event.SrcSysmonRT)
		if err != nil {
			s.log.Debug("xml parse skipped", "err", err)
			continue
		}
		if int64(ev.RecordID) > maxID {
			maxID = int64(ev.RecordID)
		}
		events = append(events, ev)
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
