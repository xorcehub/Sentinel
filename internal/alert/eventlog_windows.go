//go:build windows

package alert

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"sentinel/internal/event"
)

// EventLogAlerter writes hits to the Windows Application event log under source
// "Sentinel" (05-ALERTING.md §6).
//
// Implementation: shells to eventcreate.exe rather than binding ReportEvent
// natively. eventcreate auto-registers the source on first use (so alerting
// never fails on a fresh box), and is one less syscall binding to debug. The
// operator may pre-register the source via scripts/register-eventsource.ps1
// for a cleaner EventMessageFile; if not, eventcreate handles it.
//
// Event ID convention (05 §6): 1=critical, 2=suspicious, 3=info.
type EventLogAlerter struct {
	source string
	log    *slog.Logger
}

// NewEventLogAlerter constructs the event log writer.
func NewEventLogAlerter(source string, log *slog.Logger) *EventLogAlerter {
	if source == "" {
		source = "Sentinel"
	}
	return &EventLogAlerter{source: source, log: log}
}

// Name implements Alerter.
func (e *EventLogAlerter) Name() string { return "eventlog" }

// Alert writes one event to the Application log.
func (e *EventLogAlerter) Alert(h event.Hit) error {
	evtType, evtID := severityToEvent(h.Severity)
	body := fmt.Sprintf("[%s] %s\nRule: %s\nProc: %s\nCmd: %s",
		upper(string(h.Severity)), h.RuleName, h.RuleID,
		h.Event.Image, trunc(h.Event.CmdLine, 300))

	// eventcreate /ID <id> /T <type> /L APPLICATION /SO <source> /D "<body>"
	// Body length cap: eventcreate accepts ~31000 chars; we're well under.
	cmd := exec.Command("eventcreate.exe",
		"/ID", fmt.Sprintf("%d", evtID),
		"/T", evtType,
		"/L", "APPLICATION",
		"/SO", e.source,
		"/D", body,
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("eventcreate: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// severityToEvent maps Sentinel severity to eventcreate's /T type + sentinel ID.
func severityToEvent(sev event.Severity) (etype string, eid int) {
	switch sev {
	case event.SevCritical:
		return "WARNING", 1
	case event.SevSuspicious:
		return "INFORMATION", 2
	default:
		return "INFORMATION", 3
	}
}
