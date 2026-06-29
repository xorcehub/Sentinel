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
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"sentinel/internal/event"
	"sentinel/internal/ingest"
	"sentinel/internal/rules"
)

// Options configures an App. Logger, Ingester are required; Engine, heartbeat
// and alert hooks are optional.
type Options struct {
	Logger  *slog.Logger
	Ingester ingest.Ingester
	Engine  *rules.Engine // nil = raw passthrough (Phase 1 default)

	HeartbeatPath     string        // empty = no heartbeat file
	HeartbeatInterval time.Duration // 0 (with path) = default 5m; set <0 to disable

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
	a.log.Debug("event",
		"eid", ev.EID,
		"source", ev.Source,
		"recordid", ev.RecordID,
		"image", ev.Image,
		"cmd", truncate(ev.CmdLine, 160),
		"dst", ev.DstIP)

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
		if a.opts.OnHit != nil {
			a.opts.OnHit(h)
		}
	}
	for _, s := range res.Suppressed {
		a.stats.suppressed.Add(1)
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
	var sink io.Writer = os.Stderr
	cleanup := func() {}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log %s: %w", path, err)
		}
		sink = io.MultiWriter(os.Stderr, f)
		cleanup = func() { _ = f.Close() }
	}
	h := slog.NewTextHandler(sink, &slog.HandlerOptions{Level: level})
	return slog.New(h), cleanup, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
