package alert

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"git.sr.ht/~jackmordaunt/go-toast"
	"git.sr.ht/~jackmordaunt/go-toast/tmpl"
	"git.sr.ht/~jackmordaunt/go-toast/wintoast"
	"github.com/gen2brain/beeep"

	"sentinel/internal/event"
)

// toastAppID is the AppUserModelID under which all Sentinel toasts group in
// Action Center. Set on beeep at package init so the silent suspicious-tier
// toasts (beeep) and the loud critical-tier toasts (go-toast, via LoudToast)
// share one app identity instead of fragmenting across beeep's "DefaultAppName"
// and "Sentinel".
const toastAppID = "Sentinel"

func init() {
	beeep.AppName = toastAppID
}

// criticalNotification builds the toast config for a former-popup-tier
// (critical) alert: a looping alarm sound, long on-screen duration, looped
// audio, and an "ALERT!"-prefixed title. This is what makes a critical hit stand out
// from the silent suspicious-tier toast when the operator has disabled
// MessageBox (-popup=false). Pure (constructs the config, does not push) so
// the "what makes it loud" policy is unit-testable without firing a real
// WinRT toast. Shared by ToastAlerter (interactive session) and the
// sentinel-tray relay (Session 0) via LoudToast, so the policy lives in one
// place — tune it here and both paths update.
func criticalNotification(title, body string) toast.Notification {
	return toast.Notification{
		AppID:    toastAppID,
		Title:    "ALERT! " + title,
		Body:     body,
		Audio:    toast.LoopingAlarm,
		Duration: toast.Long,
		Loop:     true,
	}
}

// LoudToast fires a critical-tier toast (looping alarm). Best-effort: callers
// (ToastAlerter, the relay) log and swallow the error — a critical hit always
// also lands in ALERTS.log + Event Log, so a toast failure never drops the
// audit trail. Uses go-toast directly because beeep hardcodes silent audio
// (toastNotify(..., urgent=false) -> Audio=Silent), giving no way to be loud.
//
// LOOP-SAFETY: bypasses go-toast's high-level Notification.Push() and calls
// wintoast.Push(xml) with NO option, which disables the PowerShell fallback.
// That fallback writes a .ps1 to Temp and runs `powershell -ExecutionPolicy
// Bypass -File <Temp>\X.ps1` — a command line that matches EXEC-001 +
// PERSIST-001. When the COM path failed on an astral-plane title char (see
// criticalNotification), the fallback fired on every critical and self-
// triggered the rules in a ~700/hr loop. With the fallback disabled, a COM
// failure (now impossible for ASCII titles, but possible if a command line
// baked into the body carries an astral char) just returns an error the caller
// logs and drops — never a shell-out. Same lesson as the eventlog/eventcreate
// feedback fix: a Sentinel alerter must never emit a child process whose
// command line matches the very rules Sentinel enforces.
func LoudToast(title, body string) error {
	n := criticalNotification(title, body)
	// wintoast.Push needs the AppID registered (the high-level Notification.Push
	// calls SetAppData before pushing). We bypass Push to disable the PowerShell
	// fallback, so replicate the registration here. Cheap HKCU registry write;
	// idempotent. ActivationExe/Icon left empty (no click-through / branding),
	// which is fine for a loud fire-and-forget alert.
	if err := toast.SetAppData(wintoast.AppData{AppID: n.AppID}); err != nil {
		return fmt.Errorf("set toast app data: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.XMLTemplate.Execute(&buf, n); err != nil {
		return fmt.Errorf("render toast xml: %w", err)
	}
	return wintoast.Push(buf.String()) // zero options => no PowerShell fallback
}

// ToastAlerter shows a best-effort Windows toast (05-ALERTING.md §4).
//
// Uses github.com/gen2brain/beeep, which wraps the Windows toast (WinRT)
// notification API. Unlike the previous BurntToast implementation, this needs
// NO PowerShell module — beeep calls the WinRT type accelerators that ship
// built-in on Windows 10/11. Self-contained: works on a stock install.
//
// Two toast tiers, so an operator who disables MessageBox (-popup=false) still
// gets an unmissable critical signal: with popup disabled, critical hits fire
// LoudToast — a looping alarm, long duration, 🛑 title — distinct from the
// silent suspicious tier (which otherwise only lands in ALERTS.log). The loud
// critical toast is the non-blocking REPLACEMENT for the gated-off popup, so
// it fires only when popup is off (loud=true); with popup on (default) the
// critical toast stays silent (beeep) as before — the popup is already the
// attention-grabber, and a loud alarm alongside a modal box would be a
// redundant double-signal. "Best-effort" is operative: toast failure is
// logged and never propagated. beeep.Notify returns an error on failure but
// does NOT show a MessageBox fallback — this preserves our severity tiers
// (suspicious must never pop a blocking box).
//
// AUMID caveat (05-ALERTING.md §4): without registering an AppUserModelID +
// Start-Menu shortcut, toasts may not persist in Action Center. Accept as
// best-effort; never let a critical alert depend on toast alone.
type ToastAlerter struct {
	log  *slog.Logger
	loud bool // fire LoudToast for criticals — set when popup is disabled (-popup=false), making the loud toast the critical signal instead of the gated-off MessageBox
}

// NewToastAlerter constructs the best-effort toast alerter. loud=true makes
// critical-severity hits fire LoudToast (looping alarm) — wire it to the inverse
// of the popup setting so the loud toast replaces the gated-off MessageBox.
func NewToastAlerter(log *slog.Logger, loud bool) *ToastAlerter {
	return &ToastAlerter{log: log, loud: loud}
}

// Name implements Alerter.
func (t *ToastAlerter) Name() string { return "toast" }

// toastText formats the title/body for a toast. Shared by ToastAlerter (fires
// locally) and PipeToastAlerter (sends to the user-session relay).
func toastText(h event.Hit) (title, body string) {
	title = stripToastChars(fmt.Sprintf("Sentinel: %s", trunc(h.RuleName, 60)))
	body = stripToastChars(fmt.Sprintf("%s — %s", strings.ToUpper(string(h.Severity)), trunc(h.Event.Image, 80)))
	// Former-popup tier: append the command line (the MessageBox showed it) so a
	// loud critical toast is actionable, not just loud. Suspicious stays compact.
	if h.Severity == event.SevCritical && h.Event.CmdLine != "" {
		body = stripToastChars(body + " — " + trunc(h.Event.CmdLine, 100))
	}
	return
}

// stripToastChars drops characters go-toast's WinRT COM XML binding can't render,
// and neutralizes the CDATA terminator. Two breakers, both reachable from
// attacker-influenced event fields (Image/CmdLine):
//
//  1. Astral-plane (4-byte UTF-8) runes: go-toast fails XmlDocument.LoadXml
//     (0xC00CE55F) on them.
//  2. The literal sequence "]]>" — go-toast's XML template wraps Title/Body in
//     CDATA (tmpl/xml.go.tmpl), and "]]>" terminates the CDATA section early,
//     producing mismatched elements and the same LoadXml failure. Splitting it
//     to "] ]>" keeps the text readable and the envelope sealed.
//
// Either breaker breaks COM and — for beeep, which keeps go-toast's PowerShell
// fallback — triggers exactly the self-referential powershell-bypass-from-Temp
// spawn that EXEC-001/PERSIST-001 match; LoudToast (no fallback) would silently
// drop the critical toast instead. BMP chars (incl. em-dash) pass.
// ponytail: only astral is dropped; if go-toast ever widens its char support,
// remove that leg.
func stripToastChars(s string) string {
	return strings.ReplaceAll(strings.Map(func(r rune) rune {
		if r > 0xFFFF {
			return -1
		}
		return r
	}, s), "]]>", "] ]>")
}

// Alert fires a toast. Critical hits get the loud looping-alarm treatment
// (LoudToast) ONLY when loud is set (popup disabled) — so they stand out from
// the silent suspicious tier as the "different notification level" for
// former-popup-tier alerts. With popup still on, criticals use the silent beeep
// path (the MessageBox is the attention-grabber; a loud alarm too would be a
// redundant double-signal). Errors are swallowed (best-effort): the dispatcher
// must not fail an alert because the toast channel broke, and a critical hit is
// in ALERTS.log + Event Log regardless.
func (t *ToastAlerter) Alert(h event.Hit) error {
	title, body := toastText(h)
	var err error
	if h.Severity == event.SevCritical && t.loud {
		err = LoudToast(title, body)
	} else {
		err = beeep.Notify(title, body, "")
	}
	if err != nil {
		t.log.Debug("toast failed (best-effort)", "err", err,
			"rule", h.RuleID, "critical", h.Severity == event.SevCritical)
	}
	return nil
}
