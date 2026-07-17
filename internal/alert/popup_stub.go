//go:build !windows

package alert

import (
	"errors"
	"log/slog"

	"sentinel/internal/event"
)

// PopupAlerter is a no-op on non-Windows so the alert package compiles for
// tests / Linux dev. On Windows, popup_windows.go provides the real MessageBox
// implementation. Construction still succeeds (so main.go wiring is portable);
// Alert() returns a clear error if ever called on non-Windows.
type PopupAlerter struct {
	log *slog.Logger
}

func NewPopupAlerter(log *slog.Logger) *PopupAlerter {
	return &PopupAlerter{log: log}
}

func (p *PopupAlerter) Name() string { return "popup" }

func (p *PopupAlerter) Alert(h event.Hit) error {
	return errors.New("popup alerter requires Windows")
}

// InSession0 mirrors the Windows build's Session-0 detector. On non-Windows
// there is no Session 0 concept, so always false (interactive).
func InSession0() bool { return false }
