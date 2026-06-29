// Package alert implements Sentinel's alert delivery (05-ALERTING.md).
//
// The Dispatcher consumes a Hit channel and fans each Hit out to the alerters
// named in its AlertTo list. Alerters are pluggable behind the Alerter
// interface so the dispatcher is unit-testable with fakes; the production
// alerters (ALERTS.log, MessageBox, Event Log, Toast) register by name.
//
// Design rules from the dossier:
//   - ALERTS.log is ALWAYS written, all severities, even when suppressed by
//     allowlist (the audit trail). The engine handles suppression; the log
//     alerter just writes what it's given.
//   - Critical MessageBox runs in its OWN goroutine via a bounded popup queue,
//     so a blocking popup never stalls ingestion or other alerters.
//   - Alerter failure must never crash Sentinel: every Alert() is recovered
//     and logged; a critical hit that fails popup escalates to log+eventlog.
//   - Queue overflow is counted and surfaced in the heartbeat (not silently
//     dropped).
package alert

import (
	"log/slog"

	"sentinel/internal/event"
)

// Alerter is the contract every alert delivery channel implements.
type Alerter interface {
	// Name is the stable identifier matched against Hit.AlertTo entries
	// ("log", "popup", "toast", "eventlog", "webhook").
	Name() string
	// Alert delivers one hit. Must be safe for concurrent use. Errors are
	// logged by the dispatcher and never propagated to the caller — a failed
	// alerter must not drop other alerters or crash the process.
	Alert(h event.Hit) error
}

// Suppression is the alerter-side mirror of rules.Suppression (a matched hit
// that was allowlisted or deduped). The dispatcher writes these to ALERTS.log
// too, marked [SUPPRESSED], so the audit trail shows them.
type Suppression struct {
	RuleID   string
	RuleName string
	Reason   string // "allowlist" | "dedup-window"
	Event    event.Event
}

// logOf returns the logger the dispatcher uses for its own diagnostics — never
// nil (callers default to slog.Default if unset).
func logOf(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}
