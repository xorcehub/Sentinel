//go:build windows

package alert

import (
	"fmt"
	"log/slog"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinel/internal/event"
)

// Session-0 crossing. When sentinel runs as a SYSTEM Scheduled Task it lives in
// Session 0, where MessageBox renders on an invisible desktop (Session 0
// isolation) and toast gets "Access is denied". WTSSendMessageW is the Win32
// API built for exactly this: it sends a MessageBox to the ACTIVE console
// session's desktop from a service. We branch at runtime — interactive runs
// keep plain MessageBox; Session-0 runs cross over.
var (
	modKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	modWtsapi32              = windows.NewLazySystemDLL("wtsapi32.dll")
	procProcessIdToSessionId = modKernel32.NewProc("ProcessIdToSessionId")
	procWTSSendMessageW      = modWtsapi32.NewProc("WTSSendMessageW")
)

func currentSessionId() uint32 {
	var sid uint32
	r, _, _ := procProcessIdToSessionId.Call(
		uintptr(windows.GetCurrentProcessId()),
		uintptr(unsafe.Pointer(&sid)))
	if r == 0 {
		return 0
	}
	return sid
}

// InSession0 reports whether this process is NOT in the active console session
// (i.e. a SYSTEM service). When true, popup must cross sessions via WTS and
// toast is pointless (no user notification infrastructure).
func InSession0() bool {
	return currentSessionId() != windows.WTSGetActiveConsoleSessionId()
}

// PopupAlerter shows a blocking MessageBox for critical hits (05-ALERTING.md §3).
//
// Flags: MB_SETFOREGROUND | MB_TOPMOST | MB_ICONWARNING | MB_SYSTEMMODAL.
// On modern Windows MB_SYSTEMMODAL behaves like MB_TOPMOST (stays on top, modal
// frame) — it does NOT freeze input to the rest of the desktop. The operator
// can still interact with other windows; the box just stays on top. This is
// sufficient for "make sure the operator sees it" and does not over-promise.
//
// Blocking: MessageBoxW returns only when the user dismisses. The dispatcher
// routes popup hits through a bounded queue + worker goroutine so this never
// stalls ingestion.
type PopupAlerter struct {
	log *slog.Logger
}

const (
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
	mbIconWarning   = 0x00000030
	mbSystemModal   = 0x00001000
	mbOK            = 0x00000000
)

// NewPopupAlerter constructs the MessageBox alerter.
func NewPopupAlerter(log *slog.Logger) *PopupAlerter {
	return &PopupAlerter{log: log}
}

// Name implements Alerter.
func (p *PopupAlerter) Name() string { return "popup" }

// Alert shows the MessageBox. In an interactive session it blocks until
// dismissed; in Session 0 it crosses to the active console via WTSSendMessageW
// (non-blocking, so a SYSTEM daemon is never stalled by an unseen box).
func (p *PopupAlerter) Alert(h event.Hit) error {
	text, caption := formatPopup(h)
	if InSession0() {
		return p.wtsPopup(text, caption)
	}
	textW, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return fmt.Errorf("utf16 text: %w", err)
	}
	captionW, err := windows.UTF16PtrFromString(caption)
	if err != nil {
		return fmt.Errorf("utf16 caption: %w", err)
	}
	// MessageBox(handle, text, caption, flags). handle=0 = no owner window.
	flags := uint32(mbSetForeground | mbTopmost | mbIconWarning | mbSystemModal | mbOK)
	r, err := windows.MessageBox(0, textW, captionW, flags)
	if err != nil {
		return fmt.Errorf("MessageBox: %w", err)
	}
	if r == 0 {
		return fmt.Errorf("MessageBox returned 0 (no button pressed / error)")
	}
	return nil
}

// formatPopup builds the message body + window caption for a critical hit.
func formatPopup(h event.Hit) (text, caption string) {
	caption = fmt.Sprintf("🛑 SENTINEL %s — %s", h.ID, upper(string(h.Severity)))
	var b strings.Builder
	fmt.Fprintf(&b,
		"Rule:   %s  (%s)\n"+
			"Time:   %s\n"+
			"Proc:   %s\n"+
			"  cmd:  %s",
		h.RuleID, h.RuleName,
		// Local TZ so the popup wall-clock matches ALERTS.log (which uses h.Time =
		// time.Now() local); h.Event.Time is the Sysmon instant in UTC.
		h.Event.Time.Local().Format("2006-01-02 15:04:05"),
		h.Event.Image,
		trunc(h.Event.CmdLine, 300),
	)
	// Rule-relevant context (dst IP, victim process, loaded DLL, target file…)
	// so a critical popup is actionable without opening the log.
	for _, line := range contextLines(h.Event) {
		fmt.Fprintf(&b, "\n  %s", line)
	}
	fmt.Fprintf(&b, "\n\nMatch: %s", trunc(h.Matched, 200))
	return b.String(), caption
}

// wtsPopup shows the box on the active console session's desktop via
// WTSSendMessageW. bWait=FALSE: fire-and-forget (returns once posted); the box
// stays on screen until the user dismisses it, but the daemon isn't blocked.
func (p *PopupAlerter) wtsPopup(text, caption string) error {
	console := windows.WTSGetActiveConsoleSessionId()
	if console == 0xFFFFFFFF { // no active console (nobody logged in)
		return fmt.Errorf("no active console session for popup")
	}
	titleUTF, err := windows.UTF16FromString(caption)
	if err != nil {
		return fmt.Errorf("utf16 title: %w", err)
	}
	msgUTF, err := windows.UTF16FromString(text)
	if err != nil {
		return fmt.Errorf("utf16 body: %w", err)
	}
	flags := uint32(mbIconWarning | mbOK)
	var resp uint32
	ret, _, callErr := procWTSSendMessageW.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		uintptr(console),
		uintptr(unsafe.Pointer(&titleUTF[0])),
		uintptr((len(titleUTF)-1)*2), // WTSSendMessageW length is in BYTES, not wchars
		uintptr(unsafe.Pointer(&msgUTF[0])),
		uintptr((len(msgUTF)-1)*2), // passing wchars truncated body at the half-byte mark
		uintptr(flags),
		0, // timeout (ignored when bWait=FALSE)
		uintptr(unsafe.Pointer(&resp)),
		0, // bWait=FALSE
	)
	if ret == 0 {
		return fmt.Errorf("WTSSendMessageW: %w", callErr)
	}
	return nil
}
