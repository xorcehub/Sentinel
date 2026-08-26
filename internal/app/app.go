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
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"sentinel/internal/alert"
	"sentinel/internal/baseline"
	"sentinel/internal/event"
	"sentinel/internal/ingest"
	"sentinel/internal/rules"
	"sentinel/internal/snapshot"
	"sentinel/internal/state"
)

// Options configures an App. Logger, Ingester are required; Engine, heartbeat
// and alert hooks are optional.
type Options struct {
	Logger   *slog.Logger
	Ingester ingest.Ingester
	Engine   *rules.Engine // nil = raw passthrough (Phase 1 default)

	// TraceEvents enables the per-event DEBUG dump of every Sysmon event
	// (image/cmd/eid/recordid) before rule evaluation. Off by default: the dump
	// is pure passthrough (it duplicates the Windows event log and carries no
	// detection decision) and at one line per Sysmon record it dominated the
	// log. Turn on only when tuning a rule miss. Distinct from --debug so the
	// structured log stays useful without the firehose.
	TraceEvents bool

	HeartbeatPath     string        // empty = no heartbeat file
	HeartbeatInterval time.Duration // 0 (with path) = default 5m; set <0 to disable

	// TelemetryStaleThreshold is how long Sysmon event flow may go silent before
	// the heartbeat fires a HEALTH-001 critical hit (docs/hardening-plan_2308.md
	// H1). Zero value = default 10m (mirrors HeartbeatInterval's pattern);
	// negative disables the check entirely. Only Sysmon-sourced events
	// (sysmon_rt / sysmon_sweep) count as flow — baseline pseudo-events would
	// mask a dead Sysmon channel.
	TelemetryStaleThreshold time.Duration

	// Dispatcher receives Hits asynchronously (Phase 2). If set, every Hit is
	// Submit-ed non-blocking; the dispatcher fans out to alerters (log/popup/
	// eventlog/toast) on its own goroutine(s). If nil, hits are only logged +
	// passed to OnHit (Phase 1 behavior / tests).
	Dispatcher *alert.Dispatcher

	// Snapshot optionally snapshots files matching the allowlist's file_capture
	// patterns (EID 11) to a forensic vault before they can be deleted — the
	// create-and-delete dropper pattern (e.g. Cursor's Temp\ps-script-<guid>.ps1).
	// nil = feature disabled. Submit is non-blocking and runs on its own
	// goroutine (main.go starts Run + defers Close), so it can neither block
	// nor alter Evaluate. Purely additive forensics: ShouldCapture reads no
	// rule input and consults no except operator, exactly as IsLogNoise is
	// purely log-only.
	Snapshot *snapshot.Snapshotter

	// SysmonArchiveDir is the directory where Sysmon stores FileDelete (EID 23)
	// archived copies. When set, the capture hook resolves archived files from
	// EID 23 events (guaranteed-capture for create-and-delete files that are gone
	// before EID 11's poller delivery). Empty = EID 23 archive captures disabled
	// (EID 11 captures still work for files that persist).
	SysmonArchiveDir string

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
	eventsSeen      atomic.Uint64
	hits            atomic.Uint64
	suppressed      atomic.Uint64
	panicsContained atomic.Uint64
}

// App is the orchestrator. Construct with New; drive with Run.
type App struct {
	opts  Options
	log   *slog.Logger
	stats *Stats

	// supp accumulates allowlist suppressions per (rule, image) between summary
	// flushes, so an already-allowed app tripping a rule N times logs ONE
	// periodic summary line instead of N identical per-event lines. See
	// noteSuppressed / flushSuppSummary.
	suppMu sync.Mutex
	supp   map[string]*suppTally

	// lastSysmonEvent is the unix-nano time of the most recent Sysmon-sourced
	// event (H1 telemetry-lost check). 0 = none seen yet (startup grace).
	lastSysmonEvent atomic.Int64
	// healthAlerted latches the alert-once-per-stale-episode semantics: HEALTH-001
	// fires once when flow goes stale, and re-arms only when flow resumes.
	healthAlerted atomic.Bool
	// hbMu serializes writeHeartbeat: on the clean feed-close path Run calls it
	// from the drain loop while the ticker goroutine may still be mid-write, and
	// two unsynchronized os.WriteFile(O_TRUNC) calls on the same path can
	// transiently present an empty file to tailing monitors. One mutex, no torn
	// writes, deterministic final line.
	hbMu sync.Mutex
	// idGen mints conforming hit IDs for synthetic hits (HEALTH-001) — same
	// format as every rule hit, so correlation tooling sees one shape.
	idGen *rules.HitIDGen
}

// New constructs an App. Returns an error only if required fields are missing.
func New(opts Options) (*App, error) {
	if opts.Logger == nil {
		return nil, fmt.Errorf("app: Logger is required")
	}
	if opts.Ingester == nil {
		return nil, fmt.Errorf("app: Ingester is required")
	}
	a := &App{opts: opts, log: opts.Logger, stats: &Stats{}, supp: map[string]*suppTally{}, idGen: rules.NewHitIDGen()}
	// Bound the startup grace (H1): staleness accrues from process start, so a
	// Sysmon channel that was already dead before Sentinel launched still trips
	// HEALTH-001 instead of reporting flowing forever.
	a.lastSysmonEvent.Store(time.Now().UnixNano())
	return a, nil
}

// EventsSeen, Hits, Suppressed, PanicsContained — atomic snapshot getters.
func (a *App) EventsSeen() uint64      { return a.stats.eventsSeen.Load() }
func (a *App) Hits() uint64            { return a.stats.hits.Load() }
func (a *App) Suppressed() uint64      { return a.stats.suppressed.Load() }
func (a *App) PanicsContained() uint64 { return a.stats.panicsContained.Load() }

// Run drives ingestion until the context is cancelled or the feed closes.
// It returns nil on clean completion (channel closed) or ctx.Err() on cancel.
func (a *App) Run(ctx context.Context) error {
	// Derived ctx so Run's own exit (including a CLEAN ingester-channel close,
	// which does not cancel the caller's ctx) tears down the heartbeat and
	// baseline goroutines. Without this, the deferred <-hbDone / <-baselineDone
	// joins below block forever on the clean-close path and Run never returns
	// (reproduced: -mock hangs holding the single-instance mutex).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // leak guard for early returns (e.g. Ingester.Start failure); idempotent
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
	// cancel must run BEFORE the two joins above resolve their goroutines, so it
	// is deferred here (LIFO: cancel -> join baseline -> join heartbeat).
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("shutdown", "reason", ctx.Err())
			a.flushSuppSummary()
			return ctx.Err()
		case ev, ok := <-ch:
			if !ok {
				// Feed closed normally — flush the allowlist-suppression summary
				// and a final heartbeat line, then exit. final=true: no spurious
				// HEALTH-001 on the way out (a shutdown gap isn't a telemetry loss).
				a.log.Info("ingester channel closed; exiting drain loop")
				a.flushSuppSummary()
				if a.opts.HeartbeatPath != "" {
					a.writeHeartbeat(time.Now(), true)
				}
				return nil
			}
			// Per-event recover: a panic in handleEvent (rule eval, allowlist,
			// snapshot capture, alert dispatch) on an attacker-shaped event must
			// skip ONE event, not kill the drain loop (and with it the SYSTEM
			// daemon = detection blinded). Mirrors dispatcher.go's callAlerter.
			func() {
				defer func() {
					if r := recover(); r != nil {
						a.stats.panicsContained.Add(1)
						a.log.Warn("event panic contained; event skipped",
							"eid", ev.EID, "record_id", ev.RecordID, "image", ev.Image, "panic", r)
					}
				}()
				a.handleEvent(ev)
			}()
		}
	}
}

func (a *App) handleEvent(ev event.Event) (hits int, delivered bool) {
	delivered = true
	a.stats.eventsSeen.Add(1)
	// H1 telemetry-lost tracking: only REAL Sysmon events count as flow.
	// Baseline pseudo-events are excluded — they'd mask a dead Sysmon channel.
	if ev.Source == event.SrcSysmonRT || ev.Source == event.SrcSysmonSweep {
		a.lastSysmonEvent.Store(time.Now().UnixNano())
		a.healthAlerted.Store(false) // flow resumed → re-arm the stale alert
	}
	if a.opts.OnEvent != nil {
		a.opts.OnEvent(ev)
	}
	// Per-event DEBUG dump — GATED behind TraceEvents. The dump is pure
	// passthrough (no detection decision; duplicates the Windows event log) and
	// at one line per Sysmon record it was ~40% of the log, so it is off by
	// default. Enable with --trace-events when tuning a rule miss. When on, the
	// allowlist's event_log_filter still drops the configured boring patterns.
	// This is log-only — Evaluate runs regardless below, so gating can never
	// drop a detection. Engine.IsLogNoise is nil-safe (raw mode returns false).
	if a.opts.TraceEvents && !a.opts.Engine.IsLogNoise(&ev) {
		a.log.Debug("event",
			"eid", ev.EID,
			"source", ev.Source,
			"recordid", ev.RecordID,
			"image", ev.Image,
			"cmd", truncate(ev.CmdLine, 160),
			"dst", ev.DstIP)
	}

	// Snapshot capture (forensics, NOT detection): if this event's file
	// matches a file_capture pattern, snapshot it to the vault. Handles both:
	//   - EID 11 (FileCreate): capture the file at its original path (may fail
	//     with a "lost-race" if already deleted — fine, EID 23 is the backstop).
	//   - EID 23 (FileDelete): the original file is gone, but if Sysmon archived
	//     it (Archived="true"), the copy persists in SysmonArchiveDir — find it
	//     and capture that. This is the GUARANTEED path for create-and-delete
	//     files (e.g. Cursor's Temp\ps-script-<guid>.ps1) that are deleted
	//     before EID 11's poller delivery arrives.
	// Purely additive — ShouldCapture reads no rule input and Submit is
	// non-blocking (default-drop on a full buffer), so this can neither block
	// nor alter Evaluate below. Engine.ShouldCapture is nil-safe (nil Engine /
	// raw mode: no capture); nil Snapshotter = feature disabled.
	//
	// All branches log at DEBUG so an empty vault is diagnosable from
	// sentinel.log without code reading.
	if ev.EID == 11 || ev.EID == 23 {
		switch {
		case a.opts.Snapshot == nil:
			a.log.Debug("file event received but snapshot vault disabled (pass -snapshot-dir)",
				"eid", ev.EID, "image", ev.Image, "target", ev.TargetFile, "rec", ev.RecordID)
		default:
			if p := a.opts.Engine.ShouldCapture(&ev); p != "" {
				capturePath := p
				isArchive := false
				// EID 23: the original file is deleted; resolve the Sysmon archive copy.
				if ev.EID == 23 {
					if ev.Archived != "true" {
						a.log.Debug("eid 23 capture target but not archived by sysmon (ArchiveDirectory/ FileDelete rule missing?)",
							"target", ev.TargetFile, "rec", ev.RecordID, "archived", ev.Archived)
						break
					}
					if a.opts.SysmonArchiveDir == "" {
						a.log.Debug("eid 23 archived but no -sysmon-archive-dir set; cannot resolve archive copy",
							"target", ev.TargetFile, "rec", ev.RecordID)
						break
					}
					archived := snapshot.NewestArchiveFile(a.opts.SysmonArchiveDir)
					if archived == "" {
						// Distinguish access-denied (common: Sysmon locks the archive dir to
						// SYSTEM-only; the daemon runs as the user) from a genuinely empty
						// archive. This turns a silent "copy not found" into an actionable
						// "ACCESS DENIED — run scripts/check-sysmon-archive.ps1 as admin".
						access := ""
						if _, err := os.ReadDir(a.opts.SysmonArchiveDir); err != nil {
							access = err.Error()
						}
						if access != "" {
							a.log.Warn("eid 23 archived but CANNOT READ archive dir (run sentinel as SYSTEM)",
								"archive_dir", a.opts.SysmonArchiveDir, "target", ev.TargetFile, "rec", ev.RecordID, "err", access)
						} else {
							a.log.Debug("eid 23 archived but archive dir is empty",
								"archive_dir", a.opts.SysmonArchiveDir, "target", ev.TargetFile, "rec", ev.RecordID)
						}
						break
					}
					capturePath = archived
					isArchive = true
				}
				a.opts.Snapshot.Submit(snapshot.Request{
					Path:        capturePath,
					RecordID:    ev.RecordID,
					Image:       ev.Image,
					ParentImage: ev.ParentImage,
					CmdLine:     ev.CmdLine,
					User:        ev.User,
					Time:        ev.Time,
					IsArchive:   isArchive,
				})
				a.log.Debug("snapshot capture submitted", "path", capturePath, "eid", ev.EID, "rec", ev.RecordID, "image", ev.Image, "is_archive", isArchive)
			} else {
				a.log.Debug("file event not a capture target (no file_capture match)",
					"eid", ev.EID, "image", ev.Image, "target", ev.TargetFile, "rec", ev.RecordID)
			}
		}
	}

	if a.opts.Engine == nil {
		return // raw passthrough — Phase 1
	}
	res := a.opts.Engine.Evaluate(&ev)
	for _, h := range res.Hits {
		hits++
		a.stats.hits.Add(1)
		a.log.Info("HIT",
			"hid", h.ID,
			"rule", h.RuleID,
			"severity", h.Severity,
			"alert", h.AlertTo,
			"image", h.Event.Image,
			"rec", h.Event.RecordID,
			"matched", truncate(h.Matched, 120))
		// Back-link (A.4): if this hit's cmdline or target file references a
		// captured file, stamp the hid into that capture's manifest — so the
		// operator can pivot from any alert straight to the captured content.
		// Best-effort, non-blocking (manifest write is sub-ms; hits are rare).
		if a.opts.Snapshot != nil {
			a.opts.Snapshot.LinkHit(h.ID, h.Event.CmdLine, h.Event.TargetFile)
		}
		if a.opts.Dispatcher != nil {
			// non-blocking; drops+counts on overflow. A drop must propagate:
			// callers that latch alert-once state (baseline Option-A) use it to
			// avoid marking an entry alerted when its hit never reached an alerter.
			if !a.opts.Dispatcher.Submit(h) {
				delivered = false
			}
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
			// Known-good app tripped a rule -> ignored. Per-event logging flooded
			// the log (one allowed app x N rules x N connections), so accumulate
			// into the periodic summary instead; the running total is also in the
			// heartbeat's suppressed_total.
			a.noteSuppressed(s)
			continue
		}
		a.log.Info("suppressed",
			"hid", s.ID,
			"rule", s.RuleID,
			"reason", s.Reason,
			"image", s.Event.Image)
	}
	return hits, delivered
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
			a.flushSuppSummary()
			a.writeHeartbeat(time.Now(), false)
		}
	}
}

// writeHeartbeat writes the alive/counts line and runs the H1 telemetry-lost
// check: if no Sysmon event has been seen for TelemetryStaleThreshold, fire ONE
// critical HEALTH-001 hit per stale episode (re-armed by resumed flow in
// handleEvent). final=true (shutdown path) skips the check — an orderly exit
// must not manufacture a health alarm.
func (a *App) writeHeartbeat(t time.Time, final bool) {
	a.hbMu.Lock()
	defer a.hbMu.Unlock()
	// allowlist status surfaces a broken config/allowlist.json (parse error or
	// missing file) that would otherwise silently disable forensic capture
	// (ShouldCapture) and the log-noise filter — detection itself fails open,
	// but the vault going dark deserves a recurring health signal, not just the
	// one-time startup WARN from buildEngine. ok = engine + allowlist loaded;
	// degraded = engine running but allowlist off (the case to investigate);
	// n/a = no engine (raw mode / engine build failed).
	allowlist := "n/a"
	if a.opts.Engine != nil {
		if a.opts.Engine.AllowlistActive() {
			allowlist = "ok"
		} else {
			allowlist = "degraded"
		}
	}
	// H1 staleness. Seeded with process start in New(), so the startup grace is
	// bounded: if Sysmon was ALREADY dead before Sentinel started (lastSysmonEvent
	// never refreshed), staleness accrues from startup and HEALTH-001 still fires.
	// A negative threshold disables the check entirely; zero = default 10m.
	sysmon := "flowing"
	threshold := a.opts.TelemetryStaleThreshold
	if threshold == 0 {
		threshold = 10 * time.Minute
	}
	var stale time.Duration
	if last := a.lastSysmonEvent.Load(); last != 0 {
		stale = t.Sub(time.Unix(0, last))
	}
	if threshold > 0 && stale > threshold && !final {
		sysmon = "STALE"
		a.fireHealth001(t, stale, threshold)
	}
	// Dropped = dispatcher overflow counter (inbound buffer full / post-Close).
	// The dispatcher's own doc says to surface this in the heartbeat: drops are
	// otherwise invisible to the operator's periodic health signal.
	dropped := uint64(0)
	if a.opts.Dispatcher != nil {
		dropped = a.opts.Dispatcher.Dropped()
	}
	line := fmt.Sprintf("[%s] alive events_total=%d hits_total=%d suppressed_total=%d panics_contained=%d allowlist=%s sysmon=%s dropped=%d\n",
		t.Format(time.RFC3339), a.EventsSeen(), a.Hits(), a.Suppressed(), a.PanicsContained(), allowlist, sysmon, dropped)
	if err := os.WriteFile(a.opts.HeartbeatPath, []byte(line), 0o644); err != nil {
		a.log.Warn("heartbeat write failed", "err", err)
		return
	}
	a.log.Debug("heartbeat written", "path", a.opts.HeartbeatPath)
}

// fireHealth001 emits the telemetry-lost hit DIRECTLY (not through Engine
// Evaluate): there is no real Event to evaluate, so we synthesize the Hit and
// mirror handleEvent's emit block (stats + log + dispatcher + OnHit). Alert-once
// per stale episode via the healthAlerted latch. Precedent: routeBaselineDiff
// synthesizes pipeline items outside normal ingest.
func (a *App) fireHealth001(t time.Time, stale, threshold time.Duration) {
	if !a.healthAlerted.CompareAndSwap(false, true) {
		return // already alerted during this stale episode
	}
	h := event.Hit{
		ID:       a.idGen.Next(),
		RuleID:   "HEALTH-001",
		RuleName: "Sysmon telemetry lost",
		Severity: event.SevCritical,
		Matched:  fmt.Sprintf("no Sysmon events for %s (threshold %s)", stale.Truncate(time.Second), threshold),
		AlertTo:  rules.DefaultAlerters(event.SevCritical), // route identically to rule hits — no duplicated table
		Time:     t,
	}
	a.stats.hits.Add(1)
	a.log.Info("HIT",
		"hid", h.ID,
		"rule", h.RuleID,
		"severity", h.Severity,
		"alert", h.AlertTo,
		"stale", stale.Truncate(time.Second),
		"threshold", threshold,
		"matched", truncate(h.Matched, 120))
	if a.opts.Dispatcher != nil {
		a.opts.Dispatcher.Submit(h) // non-blocking; drops+counts on overflow
	}
	if a.opts.OnHit != nil {
		a.opts.OnHit(h)
	}
	a.log.Warn("telemetry lost: Sysmon events stale; HEALTH-001 fired",
		"stale", stale.Truncate(time.Second), "threshold", threshold)
}

// suppTally accumulates allowlist suppressions for one (rule, image) pair
// between summary flushes.
type suppTally struct {
	ruleID   string
	image    string
	count    uint64
	firstHid string // hid of the first suppression in this window
	lastHid  string
	lastSeen time.Time
}

// noteSuppressed records an allowlist suppression for periodic summary logging
// instead of emitting it per-event. The (rule, image) pair is the key: an
// already-allowed app tripping the same rule thousands of times collapses to a
// single summary line per flush window. Thread-safe (handleEvent runs in the
// drain loop; flushSuppSummary runs in the heartbeat / shutdown path).
func (a *App) noteSuppressed(s rules.Suppression) {
	key := s.RuleID + "\x00" + s.Event.Image
	a.suppMu.Lock()
	defer a.suppMu.Unlock()
	t, ok := a.supp[key]
	if !ok {
		t = &suppTally{ruleID: s.RuleID, image: s.Event.Image}
		a.supp[key] = t
	}
	if t.count == 0 {
		t.firstHid = s.ID
	}
	t.count++
	t.lastHid = s.ID
	t.lastSeen = time.Now()
}

// flushSuppSummary emits one DEBUG line per (rule, image) that accumulated
// allowlist suppressions since the last flush, then resets the window. Called
// on each heartbeat tick and at shutdown (drain completion + context cancel).
// At the default cadence this turns thousands of identical per-event lines
// into a compact periodic summary; the aggregate total is also reported in
// heartbeat.log's suppressed_total. A no-op (no lock churn beyond the check)
// when nothing was suppressed.
func (a *App) flushSuppSummary() {
	a.suppMu.Lock()
	if len(a.supp) == 0 {
		a.suppMu.Unlock()
		return
	}
	snap := a.supp
	a.supp = make(map[string]*suppTally)
	a.suppMu.Unlock()
	for _, t := range snap {
		if t.count == 0 {
			continue
		}
		a.log.Debug("suppressed (allowlist) summary",
			"rule", t.ruleID,
			"image", t.image,
			"count", t.count,
			"first_hid", t.firstHid,
			"last_hid", t.lastHid,
			"last_seen", t.lastSeen.Format(time.RFC3339))
	}
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

// truncate returns the first n bytes of s backed up to a rune boundary, with
// "…" appended when truncated. Rune-safe: the naive s[:n] split multibyte
// sequences in non-ASCII command lines (common on Windows), emitting invalid
// UTF-8 into the structured log. Mirrors alert.trunc.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
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
//
// Marking is gated on DELIVERY: an entry is marked alerted only when handleEvent
// produced hits AND the dispatcher accepted all of them. Otherwise it stays
// unmarked and retries next scan — failing open to duplicate alerts, never
// failing closed to permanent silence. This also covers BASE-001 missing from
// the loaded catalog (hits==0: nothing fired, nothing marked).
// ponytail ceiling: a PANIC inside handleEvent on this path is NOT contained —
// the recover lives in Run's drain loop only, so it would kill the baseline
// goroutine (entry stays unmarked = safe direction, but the loop dies). Add a
// local recover here if a panic is ever observed on attacker-shaped baseline
// pseudo-events.
func (a *App) routeBaselineDiff(clean, daily baseline.Snapshot) (newN, fired int) {
	newEntries := baseline.DiffEntries(clean, daily)
	newN = len(newEntries)
	for _, e := range newEntries {
		if a.opts.Baseline.State.BaselineAlerted(e.Key()) {
			continue // already alerted on a prior scan → Option A: stay quiet
		}
		hits, delivered := 0, true
		for _, ev := range baseline.EntriesToEvents([]baseline.Entry{e}) {
			h, d := a.handleEvent(ev) // -> engine -> BASE-001 -> dispatcher
			hits += h
			delivered = delivered && d
		}
		if !delivered {
			a.log.Warn("baseline alert NOT delivered; entry left un-marked, will retry next scan",
				"key", e.Key())
			continue
		}
		if hits == 0 {
			a.log.Warn("baseline entry matched no rule; left un-marked (is BASE-001 in the catalog?)",
				"key", e.Key())
			continue
		}
		a.opts.Baseline.State.MarkBaselineAlerted(e.Key())
		fired += hits
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
