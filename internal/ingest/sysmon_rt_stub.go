//go:build !windows

package ingest

import (
	"context"
	"errors"
	"log/slog"

	"sentinel/internal/event"
)

// stubRT is returned by NewSysmonRT on non-Windows builds. It fails loudly on
// Start so a Linux dev/CI run can never silently run with no telemetry.
type stubRT struct {
	channel string
	log     *slog.Logger
}

// NewSysmonRT constructs the real-time Sysmon ingester. On non-Windows this is
// a stub that returns an error on Start — use the mock ingester (-mock) for
// tests. (The Windows build in sysmon_rt_windows.go provides the native impl.)
// The query parameter overrides the default EID filter on Windows (ignored here).
func NewSysmonRT(channel, query string, log *slog.Logger) (Ingester, error) {
	return &stubRT{channel: channel, log: log}, nil
}

func (s *stubRT) Start(ctx context.Context) (<-chan event.Event, error) {
	return nil, errors.New("sysmon RT ingester requires Windows; build with GOOS=windows or use -mock for testing")
}
