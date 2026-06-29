//go:build windows

package ingest

import (
	"testing"

	"sentinel/internal/event"
)

// TestIsSelfChild verifies the self-ingestion filter: events whose parent is
// sentinel.exe are skipped (the poller + toast/eventlog alerters spawn
// powershell.exe children ~1/sec), while third-party processes pass through.
// The filter has no false-negative risk because an attacker cannot make
// sentinel.exe their parent without already controlling the process.
func TestIsSelfChild(t *testing.T) {
	const self = `c:\users\user01\sentinel.exe`
	s := &sysmonRT{selfExe: self}

	cases := []struct {
		name string
		ev   event.Event
		want bool
	}{
		{
			name: "powershell child of sentinel (the poller) - filtered",
			ev: event.Event{
				EID:         1,
				Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				ParentImage: `C:\Users\user01\sentinel.exe`,
			},
			want: true,
		},
		{
			name: "third-party process (attacker) - kept",
			ev: event.Event{
				EID:         1,
				Image:       `C:\Users\user01\Downloads\evil.exe`,
				ParentImage: `C:\Windows\explorer.exe`,
			},
			want: false,
		},
		{
			name: "powershell NOT spawned by sentinel - kept",
			ev: event.Event{
				EID:         1,
				Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				ParentImage: `C:\Users\user01\Downloads\dropper.exe`,
			},
			want: false,
		},
		{
			name: "network event from sentinel's child - kept (gate is EID 1 only)",
			ev: event.Event{
				EID:         3,
				ParentImage: `C:\Users\user01\sentinel.exe`,
			},
			want: false,
		},
		{
			name: "parent path in mixed case / forward-slash form - still matched",
			ev: event.Event{
				EID:         1,
				Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				ParentImage: `C:/Users/user01/sentinel.exe`,
			},
			want: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.isSelfChild(c.ev); got != c.want {
				t.Errorf("isSelfChild = %v, want %v", got, c.want)
			}
		})
	}
}

// TestIsSelfChildDisabledWhenExeUnknown: if os.Executable() failed (selfExe == ""),
// the filter must be a no-op rather than dropping everything.
func TestIsSelfChildDisabledWhenExeUnknown(t *testing.T) {
	s := &sysmonRT{selfExe: ""}
	ev := event.Event{EID: 1, ParentImage: `C:\Users\user01\sentinel.exe`}
	if s.isSelfChild(ev) {
		t.Error("filter must be disabled (return false) when selfExe is unknown")
	}
}
