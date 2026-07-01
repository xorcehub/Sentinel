// Package app is the Sentinel process orchestrator. It wires an Ingester (mock
// or native Sysmon), an optional rule Engine, structured logging, the heartbeat
// writer, and a graceful-shutdown drain loop into a single Run(ctx) method.
//
// Phase 1 acceptance (07-BUILD-PHASES.md): "events flow end-to-end to a log."
// The Engine is OPTIONAL here — if nil, the app runs in raw-passthrough mode
// (logs every event, no rule evaluation). That gives a clean first-run with no
// rules/allowlist yet, and lets Phase 2 flip the switch by passing an Engine.
package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"sentinel/internal/alert"
	"sentinel/internal/baseline"
	"sentinel/internal/event"
	"sentinel/internal/ingest"
	"sentinel/internal/rules"
	"sentinel/internal/state"
)

// Options configures an App. Logger, Ingester are required; Engine, heartbeat
// and alert hooks are optional.
type Options struct {
	Logger  *slog.Logger
	Ingester ingest.Ingester
	Engine  *rules.Engine // nil = raw passthrough (Phase 1 default)

	HeartbeatPath     string        // empty = no heartbeat file
	HeartbeatInterval time.Duration // 0 (with path) = default 5m; set <0 to disable

	// Dispatcher receives Hits asynchronously (Phase 2). If set, every Hit is
	// Submit-ed non-blocking; the dispatcher fans out to alerters (log/popup/
	// eventlog/toast) on its own goroutine(s). If nil, hits are only logged +
	// passed to OnHit (Phase 1 behavior / tests).
	Dispatcher *alert.Dispatcher

	// Baseline configures the Phase 3 baseline diff loop (daily autorunsc
	// capture diffed against a signed-off clean baseline; NEW entries fire
	// BASE-001). Zero-value (Enabled=false) leaves the loop disabled. main.go
	// enables it only when autorunsc64.exe is found, so hosts without Autoruns
	// degrade silently. The loop runs in its own goroutine and never blocks
	// ingestion or daemon launch.
	Baseline BaselineConfig

	// OnHit / OnEvent are optional callbacks (mainly for tests / self-test).
	OnHit   func(event.Hit)
	OnEvent func(event.Event)
}

// Stats holds run-since counters, read via the getters (atomic).
type Stats struct {
	eventsSeen   atomic.Uint64
	hits         atomic.Uint64
	suppressed   atomic.Uint64
}

// App is the orchestrator. Construct with New; drive with Run.
type App struct {
	opts   Options
	log    *slog.Logger
	stats  *Stats
}

// New constructs an App. Returns an error only if required fields are missing.
func New(opts Options) (*App, error) {
	if opts.Logger == nil {
		return nil, fmt.Errorf("app: Logger is required")
	}
	if opts.Ingester == nil {
		return nil, fmt.Errorf("app: Ingester is required")
	}
	return &App{opts: opts, log: opts.Logger, stats: &Stats{}}, nil
}

// EventsSeen, Hits, Suppressed — atomic snapshot getters.
func (a *App) EventsSeen() uint64 { return a.stats.eventsSeen.Load() }
func (a *App) Hits() uint64        { return a.stats.hits.Load() }
func (a *App) Suppressed() uint64  { return a.stats.suppressed.Load() }

// Run drives ingestion until the context is cancelled or the feed closes.
// It returns nil on clean completion (channel closed) or ctx.Err() on cancel.
func (a *App) Run(ctx context.Context) error {
	ch, err := a.opts.Ingester.Start(ctx)
	if err != nil {
		return fmt.Errorf("start ingester: %w", err)
	}

	// heartbeat writer (05-ALERTING.md §5): periodic alive + counts.
	hbDone := make(chan struct{})
	if a.opts.HeartbeatPath != "" {
		interval := a.opts.HeartbeatInterval
		if interval == 0 {
			interval = 5 * time.Minute
		}
		if interval > 0 {
			go a.heartbeat(ctx, interval, hbDone)
		} else {
			close(hbDone)
		}
	} else {
		close(hbDone)
	}
	defer func() { <-hbDone }()

	// Baseline diff loop (Phase 3d): async at-startup scan + daily ticker. Runs
	// in its own goroutine so the ~7-10s autorunsc capture never blocks event
	// ingestion or daemon launch. Drained at shutdown (below).
	baselineDone := make(chan struct{})
	if a.opts.Baseline.Enabled {
		go a.baselineLoop(ctx, baselineDone)
	} else {
		close(baselineDone)
	}
	defer func() { <-baselineDone }()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("shutdown", "reason", ctx.Err())
			return ctx.Err()
		case ev, ok := <-ch:
			if !ok {
				// Feed closed normally — flush a final heartbeat line and exit.
				a.log.Info("ingester channel closed; exiting drain loop")
				if a.opts.HeartbeatPath != "" {
					a.writeHeartbeat(time.Now())
				}
				return nil
			}
			a.handleEvent(ev)
		}
	}
}

func (a *App) handleEvent(ev event.Event) {
	a.stats.eventsSeen.Add(1)
	if a.opts.OnEvent != nil {
		a.opts.OnEvent(ev)
	}
	// Per-event DEBUG dump. Suppressed when the allowlist's event_log_filter
	// matches (config-driven, AND-within-entry). This is log-only — Evaluate
	// runs regardless below, so filtering the dump can never drop a detection.
	// Engine.IsLogNoise is nil-safe, so raw-passthrough mode (nil Engine) keeps
	// the full dump (useful for tuning).
	if !a.opts.Engine.IsLogNoise(&ev) {
		a.log.Debug("event",
			"eid", ev.EID,
			"source", ev.Source,
			"recordid", ev.RecordID,
			"image", ev.Image,
			"cmd", truncate(ev.CmdLine, 160),
			"dst", ev.DstIP)
	}

	if a.opts.Engine == nil {
		return // raw passthrough — Phase 1
	}
	res := a.opts.Engine.Evaluate(&ev)
	for _, h := range res.Hits {
		a.stats.hits.Add(1)
		a.log.Info("HIT",
			"rule", h.RuleID,
			"severity", h.Severity,
			"alert", h.AlertTo,
			"image", h.Event.Image,
			"matched", truncate(h.Matched, 120))
		if a.opts.Dispatcher != nil {
			a.opts.Dispatcher.Submit(h) // non-blocking; drops+counts on overflow
		}
		if a.opts.OnHit != nil {
			a.opts.OnHit(h)
		}
	}
	for _, s := range res.Suppressed {
		a.stats.suppressed.Add(1) // counter always increments — no audit loss
		// allowlist = known-good by definition; logging that decision per-event
		// floods the log (e.g. cursor.exe NET-002/003/004). Route it to DEBUG
		// (visible when tuning, silent at the default INFO level) while keeping
		// dedup-window (real rate-limiting of a live hit) at INFO.
		if s.Reason == "allowlist" {
			a.log.Debug("suppressed (allowlist)", "rule", s.RuleID, "image", s.Event.Image)
			continue
		}
		a.log.Info("suppressed",
			"rule", s.RuleID,
			"reason", s.Reason,
			"image", s.Event.Image)
	}
}

func (a *App) heartbeat(ctx context.Context, interval time.Duration, done chan<- struct{}) {
	defer close(done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.writeHeartbeat(time.Now())
		}
	}
}

func (a *App) writeHeartbeat(t time.Time) {
	line := fmt.Sprintf("[%s] alive events_total=%d hits_total=%d suppressed_total=%d\n",
		t.Format(time.RFC3339), a.EventsSeen(), a.Hits(), a.Suppressed())
	if err := os.WriteFile(a.opts.HeartbeatPath, []byte(line), 0o644); err != nil {
		a.log.Warn("heartbeat write failed", "err", err)
		return
	}
	a.log.Debug("heartbeat written", "path", a.opts.HeartbeatPath)
}

// NewLogger returns a slog logger writing to both a file (append) and stderr.
// Rotation is deferred to Phase 2 (05-ALERTING.md says rotate at 10MB × 5).
func NewLogger(path string, level slog.Level) (*slog.Logger, func(), error) {
	// stderr is wrapped to discard write errors: when the binary is built with
	// the windowsgui subsystem (production — no console window), os.Stderr is a
	// handle to a non-existent console and Write errors. io.MultiWriter stops on
	// the first error, so an unwrapped stderr would prevent the FILE from ever
	// being written. Discarding stderr errors keeps the file log intact regardless
	// of console presence. (Dev console builds still show stderr normally.)
	var sink io.Writer = safeStderr{os.Stderr}
	cleanup := func() {}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log %s: %w", path, err)
		}
		sink = io.MultiWriter(safeStderr{os.Stderr}, f)
		cleanup = func() { _ = f.Close() }
	}
	h := slog.NewTextHandler(sink, &slog.HandlerOptions{Level: level})
	return slog.New(h), cleanup, nil
}

// safeStderr wraps an io.Writer (os.Stderr) and discards write errors so that a
// broken/absent console (windowsgui subsystem) cannot break a MultiWriter that
// also contains a file. Console output still works when a console is present.
type safeStderr struct{ w io.Writer }

func (s safeStderr) Write(p []byte) (int, error) {
	_, _ = s.w.Write(p)
	return len(p), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// --- Phase 3d: baseline diff loop -------------------------------------------

// BaselineConfig configures the baseline diff loop. See Options.Baseline.
type BaselineConfig struct {
	Enabled       bool
	AutorunscPath string       // resolved path to autorunsc64.exe
	CleanPath     string       // baseline_clean.csv — the signed-off reference
	Hour          int          // daily scan hour 0-23 (0 → default 4)
	State         *state.State // the alert-once store (nil-safe: checked at call site)
}

// baselineLoop runs a scan at startup (immediate) and then once daily at Hour.
// A failed scan retries once after 15 minutes, then waits for the next
// scheduled slot. Returns when ctx is cancelled. Runs in its own goroutine so
// the autorunsc capture never blocks Run's event loop.
func (a *App) baselineLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	cfg := a.opts.Baseline
	hour := cfg.Hour
	if !(hour >= 0 && hour <= 23) {
		hour = 4 // defensive: out-of-range → sensible default
	}
	a.log.Info("baseline loop starting", "hour", hour, "clean", cfg.CleanPath)

	// At-startup scan: immediate, one retry 15m later on failure. Covers
	// "persistence landed while Sentinel was down" without delaying launch.
	a.baselineScanWithRetry(ctx, 1, 15*time.Minute, "startup")

	// Daily at Hour (local wall clock). If the machine was asleep/off at Hour,
	// the timer fires on wake (Go timers don't account for suspend), so a
	// missed slot is caught up rather than skipped.
	for {
		next := nextDailyHour(hour)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
			a.baselineScanWithRetry(ctx, 1, 15*time.Minute, "daily")
		}
	}
}

// baselineScanWithRetry runs runBaselineScan up to 1+retries times, sleeping
// interval between attempts. Logs each failure; gives up (until the next
// scheduled call) after retries are exhausted.
func (a *App) baselineScanWithRetry(ctx context.Context, retries int, interval time.Duration, tag string) {
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			a.log.Warn("baseline scan retrying after failure", "tag", tag, "in", interval)
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
		}
		if err := a.runBaselineScan(ctx); err != nil {
			a.log.Warn("baseline scan failed", "tag", tag, "attempt", attempt+1, "err", err)
			continue
		}
		return
	}
	a.log.Error("baseline scan retries exhausted; next attempt at scheduled time", "tag", tag)
}

// runBaselineScan captures the current state, diffs against the clean baseline,
// and routes NEW-and-not-yet-alerted entries through handleEvent so BASE-001
// fires (toast/log/eventlog). Option A: each (location,entry) alerts ONCE, then
// stays quiet until the clean baseline is re-snapshotted (which resets the
// alerted set via state.ResetBaselineAlerted).
func (a *App) runBaselineScan(ctx context.Context) error {
	cfg := a.opts.Baseline

	// Baseline is meaningless without the engine (BASE-001 wouldn't evaluate).
	// Skip rather than mark-without-fire (would burn an entry's one alert).
	if a.opts.Engine == nil {
		a.log.Debug("baseline scan skipped (no engine / raw mode)")
		return nil
	}
	// State holds the alert-once set; without it we cannot prevent re-alerting
	// every scan, so skip rather than spam. (main.go always sets State when
	// Enabled; this guard is purely defensive against misconfiguration.)
	if cfg.State == nil {
		a.log.Warn("baseline scan skipped (no dedup state configured)")
		return nil
	}

	// Clean baseline missing → actionable but not retryable. Warn and skip;
	// retrying won't create the file. The operator must run --baseline-snapshot.
	cleanRaw, err := os.ReadFile(cfg.CleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			a.log.Warn("no clean baseline; skipping scan. Create one: sentinel --baseline-snapshot", "path", cfg.CleanPath)
			return nil
		}
		return fmt.Errorf("read clean baseline: %w", err)
	}
	clean, err := baseline.Parse(bytes.NewReader(cleanRaw), time.Now())
	if err != nil {
		return fmt.Errorf("parse clean baseline: %w", err)
	}

	dailyRaw, err := baseline.Capture(ctx, cfg.AutorunscPath, a.log)
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	daily, err := baseline.Parse(bytes.NewReader(dailyRaw), time.Now())
	if err != nil {
		return fmt.Errorf("parse daily capture: %w", err)
	}

	newN, fired := a.routeBaselineDiff(clean, daily)
	a.log.Info("baseline scan complete",
		"new", newN, "alerted", fired, "already_alerted", newN-fired,
		"clean", len(clean.Entries), "daily", len(daily.Entries))
	return nil
}

// routeBaselineDiff diffs daily against the clean baseline and routes every
// NEW-and-not-yet-alerted entry through handleEvent (-> engine -> BASE-001 ->
// dispatcher: toast/log/eventlog). Returns (newEntryCount, firedCount).
//
// Pure logic, separated from the autorunsc capture so the Option-A alert-once
// behavior is testable without shelling out. Option A: each Entry.Key() alerts
// ONCE; subsequent scans of the same unaddressed entry stay quiet until
// state.ResetBaselineAlerted() (triggered by re-snapshotting the clean baseline).
func (a *App) routeBaselineDiff(clean, daily baseline.Snapshot) (newN, fired int) {
	newEntries := baseline.DiffEntries(clean, daily)
	newN = len(newEntries)
	for _, e := range newEntries {
		if a.opts.Baseline.State.BaselineAlerted(e.Key()) {
			continue // already alerted on a prior scan → Option A: stay quiet
		}
		a.opts.Baseline.State.MarkBaselineAlerted(e.Key())
		for _, ev := range baseline.EntriesToEvents([]baseline.Entry{e}) {
			a.handleEvent(ev) // -> engine -> BASE-001 -> dispatcher (toast/log/eventlog)
			fired++
		}
	}
	return newN, fired
}

// nextDailyHour returns the next wall-clock time at h:00 local that is strictly
// after now. Used to schedule the daily baseline scan. If the machine was
// asleep past h:00, time.After fires on wake and the scan catches up.
func nextDailyHour(h int) time.Time {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), h, 0, 0, 0, now.Location())
	for !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}
