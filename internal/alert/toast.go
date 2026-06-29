package alert

import (
	"fmt"
	"log/slog"

	"github.com/gen2brain/beeep"

	"sentinel/internal/event"
)

// ToastAlerter shows a best-effort Windows toast (05-ALERTING.md §4).
//
// Uses github.com/gen2brain/beeep, which wraps the Windows toast (WinRT)
// notification API. Unlike the previous BurntToast implementation, this needs
// NO PowerShell module — beeep calls the WinRT type accelerators that ship
// built-in on Windows 10/11. Self-contained: works on a stock install.
//
// "Best-effort" is operative: toast failure is logged and never propagated.
// MessageBox is the contract for critical alerts; toast is the bonus visible
// channel for the suspicious tier (which otherwise only lands in ALERTS.log).
// beeep.Notify returns an error on failure but does NOT show a MessageBox
// fallback — this preserves our severity tiers (suspicious must not pop a
// blocking box; only critical does, via PopupAlerter).
//
// AUMID caveat (05-ALERTING.md §4): without registering an AppUserModelID +
// Start-Menu shortcut, toasts may not persist in Action Center. Accept as
// best-effort; never let a critical alert depend on toast alone.
type ToastAlerter struct {
	log *slog.Logger
}

// NewToastAlerter constructs the best-effort toast alerter.
func NewToastAlerter(log *slog.Logger) *ToastAlerter {
	return &ToastAlerter{log: log}
}

// Name implements Alerter.
func (t *ToastAlerter) Name() string { return "toast" }

// Alert fires a toast. Errors are swallowed (best-effort).
func (t *ToastAlerter) Alert(h event.Hit) error {
	title := fmt.Sprintf("Sentinel: %s", trunc(h.RuleName, 60))
	body := fmt.Sprintf("%s — %s", upper(string(h.Severity)), trunc(h.Event.Image, 80))
	if err := beeep.Notify(title, body, ""); err != nil {
		// best-effort: log and move on. Never propagate — the dispatcher must
		// not fail an alert because the toast channel broke.
		t.log.Debug("toast failed (best-effort)", "err", err, "rule", h.RuleID)
		return nil
	}
	return nil
}
