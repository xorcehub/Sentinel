package alert

import (
	"fmt"
	"io"
	"os"
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
	return fmt.Sprintf("[%s] %-8s rule=%-12s title=%s\n    image : %s\n    cmd   : %s\n    match : %s\n    action: %s",
		ts.Format(time.RFC3339),
		upper(string(h.Severity)),
		h.RuleID,
		h.RuleName,
		h.Event.Image,
		trunc(h.Event.CmdLine, 200),
		trunc(h.Matched, 200),
		joinActions(h.AlertTo),
	)
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
