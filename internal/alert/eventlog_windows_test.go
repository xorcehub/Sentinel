//go:build windows

package alert

import (
	"log/slog"
	"strings"
	"testing"

	"sentinel/internal/event"
)

// TestSeverityToEventMapping pins the severity -> (event type, event id) map:
// Critical must render as Error (red) in Event Viewer, Suspicious as Warning
// (amber), Info as Information — and the three must be distinct. A prior
// revision collapsed Suspicious/Info to Information and left eventlogErrorType
// unused, so Critical showed amber and the lower two severities were
// indistinguishable in the event log.
func TestSeverityToEventMapping(t *testing.T) {
	cases := []struct {
		sev      event.Severity
		wantType uint16
		wantEID  int
	}{
		{event.SevCritical, eventlogErrorType, 1},
		{event.SevSuspicious, eventlogWarningType, 2},
		{event.SevInfo, eventlogInformationType, 3},
	}
	for _, c := range cases {
		gotType, gotEID := severityToEvent(c.sev)
		if gotType != c.wantType || gotEID != c.wantEID {
			t.Errorf("severityToEvent(%v) = (type=%d, eid=%d); want (type=%d, eid=%d)",
				c.sev, gotType, gotEID, c.wantType, c.wantEID)
		}
	}
}

// TestEventLogAlerterUnregisteredSourceLoudErrors proves the registration probe:
// an unregistered source must make Alert() return a clear error, NOT succeed
// silently while dropping the event (the failure mode that blinded the earlier
// "auto-registers" assumption). No real eventlog write happens here.
func TestEventLogAlerterUnregisteredSourceLoudErrors(t *testing.T) {
	src := "DefinitelyNotRegistered_xyzzy_sentinel_test"
	if sourceRegistered(src) {
		t.Fatalf("precondition: %q should not be registered", src)
	}
	a := NewEventLogAlerter(src, slog.Default())
	err := a.Alert(event.Hit{RuleID: "X", Severity: event.SevCritical})
	if err == nil {
		t.Fatal("Alert on an unregistered source returned nil — event would be silently dropped")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("error should name the missing registration, got: %v", err)
	}
}

// TestEventLogAlerterNativeWrite is the binding smoke test for the native Event
// Log path: it calls Alert() against the REAL registered "Sentinel" source and
// asserts success. This is the one check that fails if a RegisterEventSourceW /
// ReportEventW signature is wrong (exec.Command would never surface such a bug).
// Skipped if "Sentinel" isn't registered (e.g. a clean dev box without install).
// Writes exactly one event per run. Manual read-back to confirm rendering:
//
//	Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Sentinel'} -MaxEvents 1
func TestEventLogAlerterNativeWrite(t *testing.T) {
	if !sourceRegistered("Sentinel") {
		t.Skip(`"Sentinel" eventlog source not registered on this box; run scripts/register-eventsource.ps1`)
	}
	a := NewEventLogAlerter("Sentinel", slog.Default())
	h := event.Hit{
		RuleID:   "SMOKE-001",
		RuleName: "eventlog native binding smoke test",
		Severity: event.SevCritical,
		Event: event.Event{
			Image:   `C:\Windows\System32\sentinel-test.exe`,
			CmdLine: `sentinel-test.exe --self-check`,
		},
		Matched: "SMOKE-001 on sentinel-test.exe",
		AlertTo: []string{"eventlog"},
	}
	if err := a.Alert(h); err != nil {
		t.Fatalf("native ReportEventW path failed: %v", err)
	}
}
