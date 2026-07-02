//go:build windows

package alert

import (
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows"

	"sentinel/internal/event"
)

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

// Alert shows the MessageBox. Blocks until dismissed.
func (p *PopupAlerter) Alert(h event.Hit) error {
	text, caption := formatPopup(h)
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
		h.Event.Time.Format("2006-01-02 15:04:05"),
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
