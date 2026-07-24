//go:build !windows

package alert

import (
	"errors"
	"log/slog"

	"sentinel/internal/event"
)

// EventLogAlerter is a no-op on non-Windows (tests / Linux dev). On Windows,
// eventlog_windows.go provides the native ReportEventW-backed implementation.
type EventLogAlerter struct {
	log *slog.Logger
}

func NewEventLogAlerter(source string, log *slog.Logger) *EventLogAlerter {
	return &EventLogAlerter{log: log}
}

func (e *EventLogAlerter) Name() string { return "eventlog" }

func (e *EventLogAlerter) Alert(h event.Hit) error {
	return errors.New("eventlog alerter requires Windows")
}
