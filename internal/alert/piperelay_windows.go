//go:build windows

package alert

import (
	"encoding/json"
	"log/slog"

	"golang.org/x/sys/windows"

	"sentinel/internal/event"
)

// PipeToastAlerter sends toasts to the user-session sentinel-tray relay over a
// named pipe. Used when the daemon runs in Session 0 (SYSTEM), where direct
// WinRT toasts fail with "Access is denied". The relay runs in the interactive
// user's session and fires the toast there, where it persists in Action Center.
//
// Best-effort: if the relay isn't running (no user logged in, not autostarted)
// or all pipe instances are busy, the toast drops silently - the same contract
// as ToastAlerter. Never propagates errors. Architecture: docs/plan-toasts_1707.md.
type PipeToastAlerter struct {
	pipe string
	log  *slog.Logger
}

// NewPipeToastAlerter constructs a relay-backed toast alerter.
func NewPipeToastAlerter(pipe string, log *slog.Logger) *PipeToastAlerter {
	return &PipeToastAlerter{pipe: pipe, log: log}
}

// Name is "toast" so it slots into the existing alert routing (hits that
// request "toast" reach this alerter in Session 0, ToastAlerter interactively).
func (p *PipeToastAlerter) Name() string { return "toast" }

// Alert writes one toast to the relay pipe and returns. Best-effort.
func (p *PipeToastAlerter) Alert(h event.Hit) error {
	title, body := toastText(h)
	msg, err := json.Marshal(struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}{Title: title, Body: body})
	if err != nil {
		return nil // best-effort; never fail an alert on toast
	}
	namePtr, err := windows.UTF16PtrFromString(p.pipe)
	if err != nil {
		return nil
	}
	// CreateFile on a named pipe opens an instance. Fails immediately with
	// ERROR_PIPE_BUSY (or not-found) if no server instance is waiting - drop.
	hdl, err := windows.CreateFile(
		namePtr,
		windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		0, 0,
	)
	if err != nil {
		// Debug (not Warn): when the user is logged out, this fires on every
		// hit. Don't spam the log.
		p.log.Debug("toast relay unreachable (best-effort drop)", "err", err, "rule", h.RuleID)
		return nil
	}
	defer windows.CloseHandle(hdl)
	var written uint32
	if err := windows.WriteFile(hdl, msg, &written, nil); err != nil {
		p.log.Debug("toast relay write failed (best-effort drop)", "err", err, "rule", h.RuleID)
		return nil
	}
	return nil
}
