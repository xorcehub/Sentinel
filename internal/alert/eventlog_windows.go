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

// EventLogAlerter writes hits to the Windows Application event log under source
// "Sentinel" (05-ALERTING.md §6).
//
// Delivery is the native Event Log API (RegisterEventSourceW + ReportEventW),
// NOT eventcreate.exe. This is load-bearing: an earlier revision shelled to
// eventcreate.exe with the alert body on its command line. That spawned a new
// process (Sysmon EID 1) for EVERY eventlog write, carrying the rule title on
// eventcreate's command line. EVADE-001's title contains its own match tokens
// (amsi / System.dll), so each of its eventlog alerts re-triggered EVADE-001,
// which wrote another eventlog alert, in a self-sustaining loop (~1 popup/min,
// gated only by flood-collapse). The native API writes the event via RPC to the
// Event Log service — NO process is created, so NO EID 1, so that feedback class
// is structurally impossible, not merely suppressed for one binary.
//
// Registration contract (differs from the old eventcreate path): ReportEventW
// requires the source to have a registry entry under
// HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application\<source> with an
// EventMessageFile, otherwise the write is SILENTLY DROPPED (ReportEventW still
// returns success). install.ps1 registers "Sentinel" once via
// scripts/register-eventsource.ps1 (which points EventMessageFile at the OS
// EventCreate.exe, whose message table renders the first insertion string
// verbatim — confirmed by read-back). To avoid the silent-drop trap, this
// alerter probes the registration at construction and, if missing, returns a
// loud error from every Alert() so the dispatcher logs it instead of believing
// the events were written. We deliberately do NOT auto-register: that would
// re-introduce exactly the convenience cost (registry writes / message-file
// handling) that shelling to eventcreate was meant to avoid.
//
// Event ID convention (05 §6): 1=critical, 2=suspicious, 3=info.
type EventLogAlerter struct {
	source   string
	log      *slog.Logger
	unregErr error // non-nil when the source isn't registered; Alert returns it loud
}

// Event Log functions live in advapi32.dll. Bound once at package init, same
// lazy-syscall style as popup_windows.go (no cgo).
var (
	modAdvapi32            = windows.NewLazySystemDLL("advapi32.dll")
	procRegisterEventSrc   = modAdvapi32.NewProc("RegisterEventSourceW")
	procReportEvent        = modAdvapi32.NewProc("ReportEventW")
	procDeregisterEventSrc = modAdvapi32.NewProc("DeregisterEventSource")
)

// Legacy eventlog event types (Win32 EVT_*_TYPE — a render hint, not severity).
const (
	eventlogErrorType       = 1
	eventlogWarningType     = 2
	eventlogInformationType = 4
)

// NewEventLogAlerter constructs the event log writer. It probes the source's
// registration once at construction (cheap HKLM read); if missing, Alert() will
// return a loud error and the constructor logs a startup warning, so a
// misconfigured deploy is surfaced immediately rather than silently dropping
// events.
func NewEventLogAlerter(source string, log *slog.Logger) *EventLogAlerter {
	if source == "" {
		source = "Sentinel"
	}
	a := &EventLogAlerter{source: source, log: log}
	if !sourceRegistered(source) {
		a.unregErr = fmt.Errorf(
			"eventlog source %q not registered under HKLM\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Application; "+
				"run scripts/register-eventsource.ps1 (native ReportEvent does not auto-register, and without the entry writes are silently dropped)",
			source)
		logOf(log).Warn("eventlog alerter disabled: " + a.unregErr.Error())
	}
	return a
}

// Name implements Alerter.
func (e *EventLogAlerter) Name() string { return "eventlog" }

// Alert writes one event to the Application log via the native Event Log API.
//
//	RegisterEventSourceW(local, "Sentinel") -> handle
//	  ReportEventW(handle, type, cat, id, sid=nil, strings=[body], data=nil)
//	DeregisterEventSource(handle)
//
// No child process is created at any point (see the package-level note above).
func (e *EventLogAlerter) Alert(h event.Hit) error {
	if e.unregErr != nil {
		return e.unregErr
	}
	evType, evtID := severityToEvent(h.Severity)

	// Body is identical to the prior eventcreate /D payload so ALERTS.log and
	// the event's insertion string stay consistent for downstream tooling.
	var body strings.Builder
	fmt.Fprintf(&body, "[%s] %s\nHID: %s\nRule: %s\nProc: %s\nCmd: %s",
		strings.ToUpper(string(h.Severity)), h.RuleName, h.ID, h.RuleID,
		h.Event.Image, trunc(h.Event.CmdLine, 300))
	for _, line := range contextLines(h.Event) {
		fmt.Fprintf(&body, "\n%s", line)
	}
	fmt.Fprintf(&body, "\nMatch: %s", trunc(h.Matched, 200))

	bodyW, err := windows.UTF16PtrFromString(body.String())
	if err != nil {
		return fmt.Errorf("utf16 event body: %w", err)
	}
	srcW, err := windows.UTF16PtrFromString(e.source)
	if err != nil {
		return fmt.Errorf("utf16 source: %w", err)
	}

	// RegisterEventSourceW(lpUNCServerName=nil -> local, lpSourceName). Returns
	// a non-zero handle even for an unregistered source; registration is only
	// needed for the write to actually land (probed at construction above).
	handle, _, callErr := procRegisterEventSrc.Call(0, uintptr(unsafe.Pointer(srcW)))
	if handle == 0 {
		return fmt.Errorf("RegisterEventSourceW(%q): %w", e.source, callErr)
	}
	defer procDeregisterEventSrc.Call(handle)

	// ReportEventW(handle, wType, wCategory, dwEventID, pSID, wNumStrings,
	// dwDataSize, lpStrings, lpRawData). lpStrings is a pointer to an ARRAY of
	// string pointers; with one string we pass the address of a [1]*uint16.
	// pSID=nil -> the event is attributed to the daemon's own identity (SYSTEM).
	strs := [1]*uint16{bodyW}
	ret, _, callErr := procReportEvent.Call(
		handle,
		uintptr(evType),
		0, // category
		uintptr(evtID),
		0, // pSID
		1, // wNumStrings
		0, // dwDataSize
		uintptr(unsafe.Pointer(&strs[0])),
		0, // lpRawData
	)
	if ret == 0 {
		return fmt.Errorf("ReportEventW: %w", callErr)
	}
	return nil
}

// sourceRegistered reports whether source has a registry entry under
// HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application\<source>. That
// entry (with its EventMessageFile) is what ReportEventW needs to route+render
// the event; without it the write is silently dropped. KEY_READ on the Eventlog
// subtree is granted to all users by default, so this works unprivileged.
func sourceRegistered(source string) bool {
	subkey := `SYSTEM\CurrentControlSet\Services\Eventlog\Application\` + source
	subkeyW, err := windows.UTF16PtrFromString(subkey)
	if err != nil {
		return false
	}
	var h windows.Handle
	// RegOpenKeyEx returns a nil error on success. Do NOT compare against
	// windows.ERROR_SUCCESS: that is a non-nil Errno(0) const, and a nil error
	// interface is never equal to it, so the check would always read "failed"
	// and silently disable the eventlog alerter for a registered source.
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, subkeyW, 0, windows.KEY_READ, &h); err != nil {
		return false
	}
	_ = windows.RegCloseKey(h)
	return true
}

// severityToEvent maps Sentinel severity to the eventlog event type (render
// hint) and Sentinel's event ID convention (1=critical, 2=suspicious, 3=info).
// The event type is Event Viewer's icon/column: Error (red) for critical,
// Warning (amber) for suspicious, Information for info — monotonic in severity
// and uses all three EVT types, so a critical alert renders as a red Error
// (not a mere amber Warning) and suspicious is distinguishable from info.
func severityToEvent(sev event.Severity) (evType uint16, eid int) {
	switch sev {
	case event.SevCritical:
		return eventlogErrorType, 1
	case event.SevSuspicious:
		return eventlogWarningType, 2
	default:
		return eventlogInformationType, 3
	}
}
