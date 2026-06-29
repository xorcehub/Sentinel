package alert

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"sentinel/internal/event"
)

// LogAlerter writes every hit to an append-only ALERTS.log file (05-ALERTING.md
// §5). Format is one block per hit, machine-parseable + human-readable:
//
//	[2026-06-26T14:03:11+02:00] CRITICAL  rule=PERSIST-001  title=...
//	    image : C:\Windows\System32\conhost.exe
//	    cmd   : conhost.exe --headless powershell ...
//	    match : ...
//	    action: popup,toast,eventlog
//
// Suppressions are written marked [SUPPRESSED] so the audit trail records them
// even though no alert fired.
//
// Rotation at 10MB x 5 is deferred (Phase 2 polish); for now the file is
// reopened per write via a persistent handle guarded by a mutex. Concurrency:
// safe — all writes go through the mutex.
type LogAlerter struct {
	mu  sync.Mutex
	f   *os.File
	dst io.Writer // if set, writes here instead of the file (tests)
}

const alerterLogName = "log"

// NewLogAlerter opens path for append (created if absent).
func NewLogAlerter(path string) (*LogAlerter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open ALERTS.log %s: %w", path, err)
	}
	return &LogAlerter{f: f}, nil
}

// NewLogAlerterTo writes to an arbitrary io.Writer (for tests / stderr).
func NewLogAlerterTo(w io.Writer) *LogAlerter {
	return &LogAlerter{dst: w}
}

// Name implements Alerter.
func (a *LogAlerter) Name() string { return alerterLogName }

// Alert writes one hit as a formatted block.
func (a *LogAlerter) Alert(h event.Hit) error {
	block := formatHit(h)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dst != nil {
		_, err := fmt.Fprintln(a.dst, block)
		return err
	}
	if a.f == nil {
		return fmt.Errorf("ALERTS.log not open")
	}
	_, err := a.f.WriteString(block + "\n")
	return err
}

// WriteSuppression writes a suppression record (audit trail — matches are logged
// even when no alert fires). Not part of the Alerter interface; called by the
// dispatcher for each Suppression it receives.
func (a *LogAlerter) WriteSuppression(s Suppression) error {
	block := formatSuppression(s)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dst != nil {
		_, err := fmt.Fprintln(a.dst, block)
		return err
	}
	if a.f == nil {
		return fmt.Errorf("ALERTS.log not open")
	}
	_, err := a.f.WriteString(block + "\n")
	return err
}

// Close releases the underlying file handle.
func (a *LogAlerter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		err := a.f.Close()
		a.f = nil
		return err
	}
	return nil
}

func formatHit(h event.Hit) string {
	ts := h.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %-8s rule=%-12s title=%s\n    image : %s\n    cmd   : %s",
		ts.Format(time.RFC3339),
		upper(string(h.Severity)),
		h.RuleID,
		h.RuleName,
		h.Event.Image,
		trunc(h.Event.CmdLine, 200),
	)
	for _, line := range contextLines(h.Event) {
		fmt.Fprintf(&b, "\n    %s", line)
	}
	fmt.Fprintf(&b, "\n    match : %s\n    action: %s",
		trunc(h.Matched, 200),
		joinActions(h.AlertTo),
	)
	return b.String()
}

// contextLines returns human-readable "label : value" lines for whichever Event
// fields are non-empty AND relevant to the hit's EID. Process-create alerts
// (EID 1) have none of these set, so they stay compact (just image+cmd).
// Network / injection / file / registry / DNS alerts gain the context that
// makes them actionable — the dst IP:port, the victim process, the loaded DLL,
// the target file, etc. Shared by LogAlerter, PopupAlerter, EventLogAlerter so
// every channel surfaces the same context (05-ALERTING.md observability).
func contextLines(e event.Event) []string {
	var lines []string
	// EID 3 (NetworkConnect)
	if e.DstIP != "" {
		dst := e.DstIP
		if e.DstPort != 0 {
			dst = fmt.Sprintf("%s:%d", dst, e.DstPort)
		}
		if e.DstProto != "" {
			dst += "/" + e.DstProto
		}
		lines = append(lines, fmt.Sprintf("%-6s: %s", "dst", dst))
	}
	// EID 7 (ImageLoad)
	if e.ImageLoaded != "" {
		lines = append(lines, fmt.Sprintf("%-6s: %s", "loaded", e.ImageLoaded))
		if e.Signed != "" {
			lines = append(lines, fmt.Sprintf("%-6s: %s", "signed", e.Signed))
		}
		if e.Signature != "" {
			lines = append(lines, fmt.Sprintf("%-6s: %s", "signer", e.Signature))
		}
	}
	// EID 8 / 10 (CreateRemoteThread / ProcessAccess)
	if e.TargetImage != "" {
		lines = append(lines, fmt.Sprintf("%-6s: %s", "target", e.TargetImage))
		if e.GrantedAccess != "" {
			lines = append(lines, fmt.Sprintf("%-6s: %s", "access", e.GrantedAccess))
		}
	}
	// EID 11 / 23 (FileCreate / FileDelete)
	if e.TargetFile != "" {
		lines = append(lines, fmt.Sprintf("%-6s: %s", "file", e.TargetFile))
	}
	// EID 12 / 13 (Registry)
	if e.TargetRegKey != "" {
		lines = append(lines, fmt.Sprintf("%-6s: %s", "regkey", e.TargetRegKey))
		if e.Details != "" {
			lines = append(lines, fmt.Sprintf("%-6s: %s", "detail", e.Details))
		}
	}
	// EID 22 (DNSQuery)
	if e.QueryName != "" {
		lines = append(lines, fmt.Sprintf("%-6s: %s", "query", e.QueryName))
		if e.QueryResults != "" {
			lines = append(lines, fmt.Sprintf("%-6s: %s", "results", e.QueryResults))
		}
	}
	return lines
}

func formatSuppression(s Suppression) string {
	return fmt.Sprintf("[%s] SUPPRESSED rule=%-12s reason=%s\n    image : %s\n    cmd   : %s",
		time.Now().Format(time.RFC3339),
		s.RuleID, s.Reason,
		s.Event.Image,
		trunc(s.Event.CmdLine, 200),
	)
}

func upper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func joinActions(a []string) string {
	out := ""
	for i, s := range a {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
