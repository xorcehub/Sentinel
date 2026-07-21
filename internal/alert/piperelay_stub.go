//go:build !windows

package alert

import (
	"errors"
	"log/slog"

	"sentinel/internal/event"
)

// PipeToastAlerter is a no-op on non-Windows: named pipes are Windows-specific
// and so is the Session-0 toast problem. Exists so the alert package compiles
// for cross-platform tests / Linux dev.
type PipeToastAlerter struct{ log *slog.Logger }

func NewPipeToastAlerter(pipe string, log *slog.Logger) *PipeToastAlerter {
	return &PipeToastAlerter{log: log}
}

func (p *PipeToastAlerter) Name() string { return "toast" }

func (p *PipeToastAlerter) Alert(h event.Hit) error {
	return errors.New("pipe toast relay requires Windows")
}
