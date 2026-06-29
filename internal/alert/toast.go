package alert

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"sentinel/internal/event"
)

// ToastAlerter shows a best-effort Windows toast (05-ALERTING.md §4).
//
// "Best-effort" is the operative word: toast failure is logged and never
// propagated. MessageBox is the contract for critical alerts; toast is a bonus.
//
// Implementation: shells to PowerShell's BurntToast module if installed:
//
//	New-BurntToastNotification -Text "title","body"
//
// If BurntToast is absent, this errors and the dispatcher logs it once. We do
// NOT add beeep as a dependency to keep the build self-contained; the operator
// can `Install-Module BurntToast` if they want toasts.
//
// AUMID caveat (05 §4): without an AppUserModelID + Start-Menu shortcut
// registered, toasts may not reliably surface in Action Center. Accept this as
// best-effort; never let a critical alert depend on toast.
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

	// Escape single quotes for the PowerShell single-quoted string args.
	ps := fmt.Sprintf(
		`New-BurntToastNotification -Text '%s','%s'`,
		strings.ReplaceAll(title, "'", "''"),
		strings.ReplaceAll(body, "'", "''"),
	)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	if err := cmd.Run(); err != nil {
		// best-effort: log once-style and move on. Never propagate.
		t.log.Debug("toast failed (best-effort; install BurntToast for toasts)",
			"err", err, "rule", h.RuleID)
		return nil
	}
	return nil
}
