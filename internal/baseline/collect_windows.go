//go:build windows

package baseline

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Capture runs autorunsc64.exe and returns its raw CSV output (one snapshot).
// The caller writes this verbatim to baseline_clean.csv — the clean baseline is
// best stored as exactly what autorunsc emitted (no re-encoding), so future
// Parse() calls read it identically. Parse the bytes separately via Parse().
//
// Scan takes ~30-60s (signature verification across all 262 autostart
// locations); not a hot path. Callers should use a generous timeout.
//
// Flags (06-BASELINE.md §8): -accepteula -nobanner (silent); -a * (all 262
// locations); -c (CSV to stdout); -s (verify signatures -> Signer column);
// -t (normalized UTC timestamps, stable for diffing). Hashes (-h) and
// hide-Microsoft (-m) are deliberately NOT enabled — they churn / blind the diff.
func Capture(ctx context.Context, autorunscPath string, log *slog.Logger) ([]byte, error) {
	if autorunscPath == "" {
		return nil, fmt.Errorf("autorunsc path is empty")
	}
	args := []string{"-accepteula", "-nobanner", "-a", "*", "-c", "-s", "-t"}
	cmd := exec.CommandContext(ctx, autorunscPath, args...)
	// CREATE_NO_WINDOW (0x08000000): when sentinel is task-launched (windowsgui,
	// no inherited console) Windows would otherwise allocate a fresh console for
	// autorunsc64 — a flashing window during the daily baseline run. Same fix as
	// the Sysmon poller.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Info("running autorunsc (baseline capture)", "path", autorunscPath)
	start := time.Now()
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("autorunsc: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	log.Info("autorunsc complete", "duration", time.Since(start).Round(time.Second), "bytes", len(stdout.Bytes()))
	return stdout.Bytes(), nil
}
