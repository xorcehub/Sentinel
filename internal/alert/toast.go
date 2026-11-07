package alert

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"git.sr.ht/~jackmordaunt/go-toast"
	"git.sr.ht/~jackmordaunt/go-toast/tmpl"
	"git.sr.ht/~jackmordaunt/go-toast/wintoast"

	"sentinel/internal/event"
)

// toastAppID is the AppUserModelID under which all Sentinel toasts group in
// Action Center. Both tiers (SilentToast, LoudToast) push under it, so they
// share one app identity.
const toastAppID = "Sentinel"

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
// audit trail. Uses go-toast directly (no PowerShell fallback, see SilentToast).
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
	return pushNoFallback(criticalNotification(title, body))
}

// silentNotification builds the toast config for the suspicious tier (and for
// criticals while the MessageBox is the attention-grabber): no sound, short
// duration. Pure, like criticalNotification, so the policy is unit-testable.
func silentNotification(title, body string) toast.Notification {
	return toast.Notification{
		AppID:    toastAppID,
		Title:    title,
		Body:     body,
		Audio:    toast.Silent,
		Duration: toast.Short,
	}
}

// SilentToast fires a silent toast through the same no-fallback path as
// LoudToast. It replaces beeep.Notify, which calls go-toast's Push() WITH the
// PowerShell fallback. That fallback renders the toast XML unescaped
// (text/template) into a DOUBLE-QUOTED PowerShell here-string (@" ... "@) and
// runs it with -ExecutionPolicy Bypass. PowerShell expands $(...) inside such
// a string, and Title/Body carry attacker-controlled Image/CmdLine text ('$',
// '(' and ')' are legal in Windows file names) — so any COM failure turned an
// alert into code execution in the alerting process. No toast path may ever
// reach that fallback; a COM failure must only return an error.
func SilentToast(title, body string) error {
	return pushNoFallback(silentNotification(title, body))
}

// pushNoFallback renders n and pushes it via WinRT COM only. Zero wintoast
// options => no PowerShell fallback (see SilentToast / LoudToast).
func pushNoFallback(n toast.Notification) error {
	// wintoast.Push needs the AppID registered (the high-level Notification.Push
	// calls SetAppData before pushing). We bypass Push to disable the PowerShell
	// fallback, so replicate the registration here. Cheap HKCU registry write;
	// idempotent. ActivationExe/Icon left empty (no click-through / branding),
	// which is fine for a fire-and-forget alert.
	if err := toast.SetAppData(wintoast.AppData{AppID: n.AppID}); err != nil {
		return fmt.Errorf("set toast app data: %w", err)
	}
	xml, err := renderToastXML(n)
	if err != nil {
		return err
	}
	return wintoast.Push(xml) // zero options => no PowerShell fallback
}

// renderToastXML cleans Title/Body (stripToastChars) and renders the toast
// XML. Cleaning happens HERE, the one choke point every toast passes through,
// not only in toastText: the sentinel-tray relay hands pipe-supplied text
// (unauthenticated local pipe) straight to SilentToast/LoudToast, and an
// unstripped "]]>" there would close the CDATA section and let the sender add
// its own toast XML (actions, images) under the Sentinel identity.
func renderToastXML(n toast.Notification) (string, error) {
	n.Title = stripToastChars(n.Title)
	n.Body = stripToastChars(n.Body)
	var buf bytes.Buffer
	if err := tmpl.XMLTemplate.Execute(&buf, n); err != nil {
		return "", fmt.Errorf("render toast xml: %w", err)
	}
	return buf.String(), nil
}

// ToastAlerter shows a best-effort Windows toast (05-ALERTING.md §4).
//
// Uses go-toast's WinRT COM binding directly (SilentToast / LoudToast), with
// its PowerShell fallback disabled. Needs no PowerShell module; works on a
// stock Windows 10/11 install.
//
// Two toast tiers, so an operator who disables MessageBox (-popup=false) still
// gets an unmissable critical signal: with popup disabled, critical hits fire
// LoudToast — a looping alarm, long duration, 🛑 title — distinct from the
// silent suspicious tier (which otherwise only lands in ALERTS.log). The loud
// critical toast is the non-blocking REPLACEMENT for the gated-off popup, so
// it fires only when popup is off (loud=true); with popup on (default) the
// critical toast stays silent (SilentToast) as before — the popup is already the
// attention-grabber, and a loud alarm alongside a modal box would be a
// redundant double-signal. "Best-effort" is operative: toast failure is
// logged (WARN with back-off; see noteFailure) and never propagated. A failed push returns an error but
// does NOT show a MessageBox fallback — this preserves our severity tiers
// (suspicious must never pop a blocking box).
//
// AUMID caveat (05-ALERTING.md §4): without registering an AppUserModelID +
// Start-Menu shortcut, toasts may not persist in Action Center. Accept as
// best-effort; never let a critical alert depend on toast alone.
type ToastAlerter struct {
	log  *slog.Logger
	loud bool // fire LoudToast for criticals — set when popup is disabled (-popup=false), making the loud toast the critical signal instead of the gated-off MessageBox

	// Failure accounting for noteFailure. With no PowerShell fallback a COM
	// failure drops the toast, so a persistently broken toast channel must be
	// visible at the default log level, not only at debug.
	mu           sync.Mutex
	failed       uint64
	lastFailWarn time.Time     // zero = no WARN yet in the current failure streak
	warnEvery    time.Duration // current WARN interval; 0 = toastFailWarnEvery
}

// toastFailWarnEvery is the first WARN interval of a failure streak. Each
// further WARN in the same streak doubles it, up to toastFailWarnMax, so a
// permanently broken toast channel (e.g. "Access is denied" on every push)
// settles at ~1 line per hour instead of 1440 a day. A successful push ends
// the streak (noteSuccess) and the next failure warns at once again.
const (
	toastFailWarnEvery = time.Minute
	toastFailWarnMax   = time.Hour
)

// noteFailure counts a failed push and logs it: WARN when the current
// back-off interval has passed (with failed_total), DEBUG otherwise. now is
// injected so tests control the clock.
func (t *ToastAlerter) noteFailure(err error, h event.Hit, now time.Time) {
	t.mu.Lock()
	t.failed++
	total := t.failed
	if t.warnEvery == 0 {
		t.warnEvery = toastFailWarnEvery
	}
	warn := t.lastFailWarn.IsZero() || now.Sub(t.lastFailWarn) >= t.warnEvery
	if warn {
		if !t.lastFailWarn.IsZero() {
			t.warnEvery = min(2*t.warnEvery, toastFailWarnMax)
		}
		t.lastFailWarn = now
	}
	next := t.warnEvery
	t.mu.Unlock()
	args := []any{"err", err, "rule", h.RuleID, "critical", h.Severity == event.SevCritical, "failed_total", total}
	if warn {
		args = append(args, "next_warn_after", next)
	}
	if warn {
		t.log.Warn("toast failed (dropped; hit is still in ALERTS.log + Event Log)", args...)
		return
	}
	t.log.Debug("toast failed (best-effort)", args...)
}

// noteSuccess ends a failure streak: the back-off resets, so the next failure
// after a working push warns immediately.
func (t *ToastAlerter) noteSuccess() {
	t.mu.Lock()
	t.lastFailWarn = time.Time{}
	t.warnEvery = 0
	t.mu.Unlock()
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
	// No stripToastChars here: renderToastXML cleans every toast at push time
	// (also the relay's, which arrives over the pipe).
	title = fmt.Sprintf("Sentinel: %s", trunc(h.RuleName, 60))
	body = fmt.Sprintf("%s — %s", strings.ToUpper(string(h.Severity)), trunc(h.Event.Image, 80))
	// Former-popup tier: append the command line (the MessageBox showed it) so a
	// loud critical toast is actionable, not just loud. Suspicious stays compact.
	if h.Severity == event.SevCritical && h.Event.CmdLine != "" {
		body = body + " — " + trunc(h.Event.CmdLine, 100)
	}
	return
}

// stripToastChars drops characters go-toast's WinRT COM XML binding can't render,
// and neutralizes the CDATA terminator. Three breakers, all reachable from
// attacker-influenced event fields (Image/CmdLine):
//
//  1. Astral-plane (4-byte UTF-8) runes: go-toast fails XmlDocument.LoadXml
//     (0xC00CE55F) on them.
//  2. The literal sequence "]]>" — go-toast's XML template wraps Title/Body in
//     CDATA (tmpl/xml.go.tmpl), and "]]>" terminates the CDATA section early,
//     producing mismatched elements and the same LoadXml failure. Splitting it
//     to "] ]>" keeps the text readable and the envelope sealed.
//  3. Characters illegal in XML 1.0 (C0 controls other than tab/LF/CR, and
//     U+FFFE/U+FFFF): LoadXml rejects them anywhere in the document, CDATA
//     included. Dropped for the same reason as (1).
//
// Any breaker makes the COM push fail, which (with no fallback) silently drops
// the toast; the hit is still in ALERTS.log + Event Log. BMP chars (incl.
// em-dash) pass.
//
// ponytail: only astral is dropped; if go-toast ever widens its char support,
// remove that leg.
func stripToastChars(s string) string {
	return strings.ReplaceAll(strings.Map(func(r rune) rune {
		if r > 0xFFFF || r == 0xFFFE || r == 0xFFFF {
			return -1
		}
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s), "]]>", "] ]>")
}

// Alert fires a toast. Critical hits get the loud looping-alarm treatment
// (LoudToast) ONLY when loud is set (popup disabled) — so they stand out from
// the silent suspicious tier as the "different notification level" for
// former-popup-tier alerts. With popup still on, criticals use the silent
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
		err = SilentToast(title, body)
	}
	if err != nil {
		t.noteFailure(err, h, time.Now())
	} else {
		t.noteSuccess()
	}
	return nil
}
