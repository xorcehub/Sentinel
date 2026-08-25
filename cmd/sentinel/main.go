// Command sentinel is the entry point for the Sentinel endpoint guard.
//
// Usage:
//
//	sentinel [-rules DIR] [-allowlist FILE] [-state FILE] [-log FILE]
//	         [-heartbeat FILE] [-mock] [-mock-events N] [-raw]
//
// Phase 1 (07-BUILD-PHASES.md): launch, acquire single-instance mutex, ingest
// Sysmon events, write them to the log + heartbeat. The rule Engine is wired in
// but optional: with -raw (or if rules/allowlist can't load) the app runs in
// passthrough mode (events logged, no evaluation) rather than refusing to start.
//
// Signal handling: only os.Interrupt (Ctrl+C) is deliverable on Windows
// (02-ARCHITECTURE.md §6) — SIGTERM/SIGHUP do not exist there. We cancel on it.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"sentinel/internal/alert"
	"sentinel/internal/allowlist"
	"sentinel/internal/app"
	"sentinel/internal/baseline"
	"sentinel/internal/event"
	"sentinel/internal/ingest"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/proc"
	"sentinel/internal/rules"
	"sentinel/internal/selftest"
	"sentinel/internal/sigmaeval"
	"sentinel/internal/sigverify"
	"sentinel/internal/snapshot"
	"sentinel/internal/state"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		failExit(err)
	}
}

// failExit reports a fatal error from run(). Under the production windowsgui
// build os.Stderr is a dead handle, so printing there alone would make a
// startup failure (mutex conflict, missing rules dir, locked state.db) silent.
// We also append the error to sentinel.log via a direct file open — best-effort
// (the structured logger may not be initialized yet at the failure point, and
// the log file may not be openable). Console builds still get stderr output.
func failExit(err error) {
	// Best-effort log file write. Don't use the slog logger: it may not exist
	// yet (failure can happen before NewLogger), and we want a clear fatal marker.
	if f, ferr := os.OpenFile("sentinel.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); ferr == nil {
		fmt.Fprintf(f, "%s [FATAL] sentinel: %v\n", time.Now().Format(time.RFC3339), err)
		_ = f.Close()
	}
	// Best-effort stderr (dead under windowsgui, works for console builds).
	fmt.Fprintf(os.Stderr, "sentinel: %v\n", err)
	os.Exit(1)
}

type flags struct {
	rulesDir          string
	allowlistPath     string
	statePath         string
	logPath           string
	heartbeatPath     string
	alertsPath        string
	debug             bool
	traceEvents       bool
	mock              bool
	mockEvents        int
	raw               bool
	mutexName         string
	sysmonChannel     string
	sysmonQuery       string
	sysmonNative      bool
	selfTest          bool
	baselineSnapshot  bool
	baselineNow       bool
	baselineClean     string
	baselineHour      int
	autorunsc         string
	snapshotDir       string
	snapshotPerFileKB int
	snapshotTotalMB   int
	sysmonArchiveDir  string
	popup             bool
}

func parseFlags(args []string) (*flags, *flag.FlagSet) {
	f := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	out := &flags{}
	f.StringVar(&out.rulesDir, "rules", "rules.d", "rules directory (Sigma .yml)")
	f.StringVar(&out.allowlistPath, "allowlist", "config/allowlist.json", "allowlist JSONC")
	f.StringVar(&out.statePath, "state", "state.db", "bbolt state file path")
	f.StringVar(&out.logPath, "log", "sentinel.log", "log file (append)")
	f.StringVar(&out.heartbeatPath, "heartbeat", "heartbeat.log", "heartbeat file")
	f.StringVar(&out.alertsPath, "alerts", "ALERTS.log", "ALERTS.log file (append)")
	f.BoolVar(&out.debug, "debug", true, "debug-level logging")
	f.BoolVar(&out.traceEvents, "trace-events", false, "log every raw Sysmon event at DEBUG (very verbose; duplicates the Windows event log — for rule tuning only)")
	f.BoolVar(&out.mock, "mock", false, "use the mock ingester (testing / smoke)")
	f.IntVar(&out.mockEvents, "mock-events", 5, "number of mock events to emit (with -mock)")
	f.BoolVar(&out.raw, "raw", false, "raw passthrough: log events, do not run the engine")
	f.StringVar(&out.mutexName, "mutex", "", "single-instance mutex name (default: Global\\Sentinel-Running-<current-user>)")
	f.StringVar(&out.sysmonChannel, "sysmon-channel", "Microsoft-Windows-Sysmon/Operational", "Sysmon event channel")
	f.StringVar(&out.sysmonQuery, "sysmon-query", "", "override the Sysmon XPath filter (diagnostic; use \"*\" to subscribe to all events)")
	f.BoolVar(&out.sysmonNative, "sysmon-native", false, "use the experimental native EvtSubscribe ingester (known broken: ERROR_INVALID_PARAMETER)")
	f.BoolVar(&out.selfTest, "self-test", false, "run the incident-coverage regression against the catalog and exit")
	f.BoolVar(&out.baselineSnapshot, "baseline-snapshot", false, "capture an autorunsc baseline to --baseline-clean and exit")
	f.BoolVar(&out.baselineNow, "baseline-now", false, "diff current autorunsc state vs --baseline-clean; print new entries; exit")
	f.StringVar(&out.baselineClean, "baseline-clean", "baseline_clean.csv", "baseline CSV file (clean reference for the daily diff)")
	f.IntVar(&out.baselineHour, "baseline-hour", 4, "hour (0-23, local) for the daemon's daily baseline scan")
	f.StringVar(&out.autorunsc, "autorunsc", "", "path to autorunsc64.exe (default: search exe dir, C:\\Tools\\Autoruns, PATH)")
	f.StringVar(&out.snapshotDir, "snapshot-dir", "", "directory to snapshot file_capture-matched files into before they're deleted (empty = disabled; see config/allowlist.json file_capture)")
	f.IntVar(&out.snapshotPerFileKB, "snapshot-per-file-kb", 2048, "max KB copied per captured file (0 = unlimited; oversize files are truncated with status=truncated)")
	f.IntVar(&out.snapshotTotalMB, "snapshot-total-mb", 500, "max total MB of the snapshot vault; oldest captures evicted when exceeded (0 = unlimited)")
	f.StringVar(&out.sysmonArchiveDir, "sysmon-archive-dir", "", "Sysmon FileDelete archive directory (where <ArchiveDirectory> stores EID 23 archived copies). Enables guaranteed capture of create-and-delete files that are gone before EID 11 delivery. Empty = EID 23 archive captures disabled.")
	f.BoolVar(&out.popup, "popup", true, "show a blocking MessageBox for critical alerts (default on). Set -popup=false to suppress popups: critical hits then surface as a loud looping-alarm toast instead of a click-away box (suspicious-tier toasts stay silent either way).")
	return out, f
}

func run(args []string) error {
	fl, fs := parseFlags(args)
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resolve path flags relative to the EXE directory, not the launch CWD.
	// Task Scheduler launches with CWD = %SystemRoot%\system32 (NOT the exe's
	// folder), which would make every relative default resolve against system32
	// — rules.d/ wouldn't be found (engine degrades to no-op passthrough), and
	// state.db/sentinel.log/ALERTS.log would get created in system32. Explicit
	// absolute paths from the CLI pass through unchanged. Must run before
	// --self-test (which also uses fl.rulesDir).
	resolveExeRelative(fl)

	// --self-test: run the incident-coverage regression against the catalog and
	// exit. No mutex, no ingestion, no alerters — pure engine check. Portable.
	if fl.selfTest {
		return runSelfTest(fl)
	}

	// --baseline-snapshot / --baseline-now: Phase 3 CLI (06-BASELINE.md §3).
	// One-shot autorunsc capture / diff; exit. No mutex, no daemon. Output goes
	// to stdout (use a console build: `go build ./cmd/sentinel`) and to the
	// baseline-clean file; under the windowsgui build stdout is a dead handle.
	if fl.baselineSnapshot {
		return runBaselineSnapshot(fl)
	}
	if fl.baselineNow {
		return runBaselineNow(fl)
	}

	// Single-instance enforcement. If mutexName is unset (the default), derive
	// a per-user name at runtime — so no username is hardcoded in source.
	mutexName := fl.mutexName
	if mutexName == "" {
		mutexName = defaultMutexName()
	}
	owned, release, err := proc.Acquire(mutexName)
	if err != nil {
		return fmt.Errorf("acquire mutex: %w", err)
	}
	if !owned {
		return errors.New("another sentinel instance is already running; exiting")
	}
	defer release()

	// Logging: file + stderr, structured.
	level := slog.LevelInfo
	if fl.debug {
		level = slog.LevelDebug
	}
	logger, logCleanup, err := app.NewLogger(fl.logPath, level)
	if err != nil {
		return err
	}
	defer logCleanup()
	logger.Info("sentinel starting", "pid", os.Getpid(), "mock", fl.mock, "raw", fl.raw)

	// State (bbolt dedup). Opened even in raw mode so it's ready for Phase 2.
	st, err := state.Open(fl.statePath)
	if err != nil {
		return fmt.Errorf("open state: %w", err)
	}
	defer st.Close()

	// Engine: optional. Skip on -raw, or if rules/allowlist can't load (degrade
	// to passthrough with a loud warning rather than refusing to run).
	var eng *rules.Engine
	if !fl.raw {
		eng, err = buildEngine(fl, st, logger)
		if err != nil {
			logger.Warn("engine build failed; running in raw passthrough mode", "err", err)
			eng = nil
		}
	} else {
		logger.Info("raw mode requested; engine disabled")
	}

	// Ingester: mock (testable anywhere) or native Sysmon RT (Windows).
	ing, err := buildIngester(fl, logger)
	if err != nil {
		return err
	}

	// Context cancelled by Ctrl+C (the only deliverable signal on Windows).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Build the alert dispatcher (Phase 2). ALERTS.log is always wired; the
	// Windows-only alerters (popup/eventlog/toast) register too. If the log
	// file can't open, degrade to no-dispatcher (hits still logged via slog).
	disp := buildDispatcher(fl, logger)
	if disp != nil {
		go disp.Run(ctx)
		defer disp.Close()
	}

	// Snapshot vault: copies file_capture-matched files (EID 11) to disk before
	// they can be deleted (the Cursor Temp\ps-script-<guid>.ps1 create-and-delete
	// pattern). Disabled unless --snapshot-dir is set. Runs on its own goroutine;
	// Submit is non-blocking so a capture flood never stalls ingestion or
	// detection (see internal/snapshot).
	snap := buildSnapshot(fl, logger)
	if snap != nil {
		go snap.Run(ctx)
		defer snap.Close()
	}

	a, err := app.New(app.Options{
		Logger:           logger,
		Ingester:         ing,
		Engine:           eng,
		TraceEvents:      fl.traceEvents,
		HeartbeatPath:    fl.heartbeatPath,
		Dispatcher:       disp,
		Snapshot:         snap,
		SysmonArchiveDir: fl.sysmonArchiveDir,
		Baseline:         buildBaseline(fl, st, logger),
	})
	if err != nil {
		return err
	}
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	logger.Info("sentinel exited cleanly")
	return nil
}

// buildBaseline configures the Phase 3d baseline diff loop. Enabled only when
// autorunsc64.exe is findable, so a host without Autoruns degrades silently
// (one warning at startup, no daily failures). The loop itself additionally
// handles a missing clean baseline per-scan (warn + skip), so first-run before
// --baseline-snapshot is not a flood.
func buildBaseline(fl *flags, st *state.State, logger *slog.Logger) app.BaselineConfig {
	path, err := findAutorunsc(fl.autorunsc)
	if err != nil {
		logger.Warn("baseline diff disabled: autorunsc64.exe not found; Phase 3 catch-by-result unavailable",
			"hint", "install Sysinternals Autoruns or pass -autorunsc <path>")
		return app.BaselineConfig{}
	}
	return app.BaselineConfig{
		Enabled:       true,
		AutorunscPath: path,
		CleanPath:     fl.baselineClean,
		Hour:          fl.baselineHour,
		State:         st,
	}
}

// buildSnapshot assembles the file-capture vault. Returns nil (feature off)
// when --snapshot-dir is empty or the vault can't be initialized — in both
// cases the daemon continues without snapshotting (detection is unaffected).
// Mirrors buildDispatcher's degrade-silently contract.
func buildSnapshot(fl *flags, logger *slog.Logger) *snapshot.Snapshotter {
	if fl.snapshotDir == "" {
		logger.Info("snapshot vault disabled (no --snapshot-dir)")
		return nil
	}
	s, err := snapshot.New(fl.snapshotDir, fl.snapshotPerFileKB, fl.snapshotTotalMB, logger)
	if err != nil {
		logger.Warn("snapshot vault init failed; file capture disabled", "dir", fl.snapshotDir, "err", err)
		return nil
	}
	logger.Info("snapshot vault active", "dir", fl.snapshotDir, "perFileKB", fl.snapshotPerFileKB, "totalMB", fl.snapshotTotalMB)
	if fl.sysmonArchiveDir != "" {
		logger.Info("sysmon FileDelete archive capture enabled", "archive_dir", fl.sysmonArchiveDir)
	}
	return s
}

// buildDispatcher assembles the alert delivery chain. ALERTS.log is always
// present (the audit trail); popup/eventlog/toast are Windows-only. Returns
// nil if the mandatory ALERTS.log can't be opened (so the app degrades to
// slog-only rather than refusing to run).
func buildDispatcher(fl *flags, logger *slog.Logger) *alert.Dispatcher {
	logPath := fl.alertsPath
	if logPath == "" {
		logPath = "ALERTS.log"
	}
	logAlerter, err := alert.NewLogAlerter(logPath)
	if err != nil {
		logger.Warn("ALERTS.log open failed; alerts will be slog-only", "path", logPath, "err", err)
		return nil
	}
	// Toast needs a user profile + notification infrastructure that Session 0
	// (SYSTEM service) lacks — it only spams "Access is denied" in the log.
	// Pop up via WTS works there, so only toast is gated. log+eventlog+popup run
	// in all modes.
	alerters := []alert.Alerter{
		logAlerter,
		alert.NewEventLogAlerter("Sentinel", logger),
	}
	if fl.popup {
		alerters = append(alerters, alert.NewPopupAlerter(logger))
	} else {
		// -popup=false: MessageBox suppressed. Critical hits still carry
		// "popup" in their engine-declared AlertTo, but the dispatcher skips it
		// silently (no popup alerter registered) and the already-present
		// "toast" channel fires a loud looping-alarm toast instead. log+
		// eventlog are unchanged.
		logger.Info("MessageBox popups disabled (-popup=false); critical alerts route to a loud looping-alarm toast")
	}
	// The loud critical toast (looping alarm) is the non-blocking REPLACEMENT
	// for the gated-off popup: only escalate criticals to a loud toast when the
	// popup is disabled. With popup on, criticals still toast silently alongside
	// the MessageBox — a loud alarm too would be a redundant double-signal.
	loudCritical := !fl.popup
	if alert.InSession0() {
		// Session 0 (SYSTEM) can't fire WinRT toasts directly ("Access is
		// denied"). Hand them to the user-session relay over a named pipe.
		alerters = append(alerters, alert.NewPipeToastAlerter(`\\.\pipe\sentinel-toast`, logger, loudCritical))
		logger.Info("running in Session 0; toast via relay pipe")
	} else {
		alerters = append(alerters, alert.NewToastAlerter(logger, loudCritical))
	}
	return alert.New(alerters, 256, logger)
}

// runSelfTest loads the catalog and runs the incident-coverage regression and
// writes a per-case report. Returns an error if any case failed (exit code
// reflects pass/fail).
//
// Output handling: the report is written to self-test.txt next to the EXE AND
// to stdout. The file is mandatory because the production build uses
// -ldflags "-H windowsgui" - under the GUI subsystem os.Stdout is a dead
// handle, so fmt.Printf prints to nothing. The file always works regardless of
// subsystem. For interactive use, build a console binary
// (`go build ./cmd/sentinel` without the windowsgui ldflag) and stdout works too.
func runSelfTest(fl *flags) error {
	catalog, err := loadRulesDir(fl.rulesDir)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	if len(catalog) == 0 {
		return fmt.Errorf("no .yml rule files in %s", fl.rulesDir)
	}
	results, allPassed, err := selftest.Run(catalog)
	if err != nil {
		return err
	}

	var b strings.Builder
	passed := 0
	for _, r := range results {
		mark := "✓"
		if !r.Passed {
			mark = "✗"
		} else {
			passed++
		}
		fmt.Fprintf(&b, "  %s %s\n", mark, r.Case.Name)
		if !r.Passed {
			fmt.Fprintf(&b, "      fired: %v\n      %s\n", r.Fired, r.Detail)
		} else if len(r.Fired) > 0 {
			fmt.Fprintf(&b, "      fired: %v\n", r.Fired)
		}
	}
	fmt.Fprintf(&b, "\n%d/%d cases passed\n", passed, len(results))
	if !allPassed {
		b.WriteString("self-test FAILED\n")
	} else {
		b.WriteString("self-test PASSED\n")
	}

	report := b.String()
	// Dual-write: stdout (console builds) + self-test.txt (mandatory; works
	// under windowsgui where stdout is a dead handle). The file IS the contract
	// for the production build.
	reportPath, werr := writeReport("self-test", report)
	if werr != nil {
		return fmt.Errorf("self-test: %w", werr)
	}

	if !allPassed {
		return fmt.Errorf("self-test FAILED (see %s)", reportPath)
	}
	return nil
}

// runBaselineSnapshot captures an autorunsc baseline and writes it verbatim to
// fl.baselineClean. The operator runs this once on a verified-clean machine,
// reviews + commits the CSV as the diff reference (06-BASELINE.md §3). One-shot:
// no daemon, no mutex.
func runBaselineSnapshot(fl *flags) error {
	autorunscPath, err := findAutorunsc(fl.autorunsc)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	raw, err := baseline.Capture(ctx, autorunscPath, slog.Default())
	if err != nil {
		return err
	}
	// Validate the capture parses before staking the clean baseline on it.
	snap, err := baseline.Parse(bytes.NewReader(raw), time.Now())
	if err != nil {
		return fmt.Errorf("captured output failed to parse: %w", err)
	}
	if err := os.WriteFile(fl.baselineClean, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", fl.baselineClean, err)
	}
	// Re-establishing the clean baseline changes the frame of reference: any
	// previously-NEW entry the operator has now accepted into clean must not be
	// suppressed by a stale "already alerted" record if it ever reappears. Reset
	// the Phase 3d alert-once set. Best-effort (state may be locked by a running
	// daemon; bbolt's 2s write-lock timeout normally suffices).
	var warn string
	if st, serr := state.Open(fl.statePath); serr == nil {
		if rerr := st.ResetBaselineAlerted(); rerr != nil {
			warn = fmt.Sprintf("warning: reset baseline alert set: %v\n", rerr)
		}
		st.Close()
	}
	var b strings.Builder
	b.WriteString(warn)
	fmt.Fprintf(&b, "wrote %s (%d entries, %d bytes)\n", fl.baselineClean, len(snap.Entries), len(raw))
	b.WriteString("Review the file, then commit it as the clean baseline.\n")
	if _, werr := writeReport("baseline-snapshot", b.String()); werr != nil {
		return werr
	}
	return nil
}

// runBaselineNow captures the current state and diffs it against the clean
// baseline, printing every NEW persistence entry. This is the Phase 3 proof:
// run it after installing something (or simulating persistence) to see the diff
// surface it. In Phase 3d the daemon wires the diff through the engine so
// BASE-001 toasts/logs these automatically (daily ticker + at-startup).
func runBaselineNow(fl *flags) error {
	autorunscPath, err := findAutorunsc(fl.autorunsc)
	if err != nil {
		return err
	}
	cleanRaw, err := os.ReadFile(fl.baselineClean)
	if err != nil {
		return fmt.Errorf("read clean baseline %s: %w (run --baseline-snapshot first)", fl.baselineClean, err)
	}
	clean, err := baseline.Parse(bytes.NewReader(cleanRaw), time.Now())
	if err != nil {
		return fmt.Errorf("parse clean baseline: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dailyRaw, err := baseline.Capture(ctx, autorunscPath, slog.Default())
	if err != nil {
		return err
	}
	daily, err := baseline.Parse(bytes.NewReader(dailyRaw), time.Now())
	if err != nil {
		return fmt.Errorf("parse daily capture: %w", err)
	}
	events := baseline.Diff(clean, daily)

	var b strings.Builder
	if len(events) == 0 {
		fmt.Fprintf(&b, "no new persistence entries (clean=%d entries, daily=%d)\n", len(clean.Entries), len(daily.Entries))
	} else {
		fmt.Fprintf(&b, "%d NEW persistence entr%s (clean=%d, daily=%d):\n", len(events), pluralIES(len(events)), len(clean.Entries), len(daily.Entries))
		for _, e := range events {
			where := e.TargetRegKey
			if where == "" {
				where = e.TargetFile
			}
			fmt.Fprintf(&b, "  NEW  %s\n", where)
			if e.User != "" {
				fmt.Fprintf(&b, "        signer: %s\n", e.User)
			}
			if e.CmdLine != "" {
				fmt.Fprintf(&b, "        launch: %s\n", e.CmdLine)
			}
		}
		b.WriteString("\n(The daemon routes these through BASE-001 -> toast/log/eventlog automatically.)\n")
	}
	if _, werr := writeReport("baseline-now", b.String()); werr != nil {
		return werr
	}
	return nil
}

// findAutorunsc resolves the autorunsc64.exe path: explicit -autorunsc flag,
// then next to sentinel.exe, then common install dirs, then PATH. Returns an
// actionable error (with the flag hint) if none found.
func findAutorunsc(flagPath string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}
	var candidates []string
	if dir := exeDir(); dir != "" {
		candidates = append(candidates, filepath.Join(dir, "autorunsc64.exe"))
	}
	candidates = append(candidates,
		`C:\Tools\Autoruns\autorunsc64.exe`,
		`C:\Program Files\Sysinternals\Autoruns\autorunsc64.exe`,
	)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath("autorunsc64.exe"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("autorunsc64.exe not found; pass -autorunsc <path> (e.g. C:\\Tools\\Autoruns\\autorunsc64.exe)")
}

func pluralIES(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// writeReport writes text to stdout (best-effort — a dead handle under the
// windowsgui production build) AND to <name>.txt next to the exe (mandatory —
// works under both console and windowsgui subsystems). All three one-shot
// commands (self-test, baseline-snapshot, baseline-now) route their
// human-readable output through this so a run under the windowsgui build
// (e.g. a Task Scheduler action) still produces a visible result file.
// Returns the report path (so callers can reference it in errors) and an
// error only if the file write fails (stdout failures are ignored).
func writeReport(name, text string) (reportPath string, err error) {
	fmt.Print(text) // best-effort; silent under windowsgui
	reportPath = filepath.Join(exeDir(), name+".txt")
	if exeDir() == "" {
		reportPath = name + ".txt" // fallback to CWD if exe dir unknown
	}
	if werr := os.WriteFile(reportPath, []byte(text), 0o644); werr != nil {
		return reportPath, fmt.Errorf("write %s: %w (report below)\n%s", reportPath, werr, text)
	}
	return reportPath, nil
}

func buildEngine(fl *flags, st *state.State, logger *slog.Logger) (*rules.Engine, error) {
	rulesYAML, err := loadRulesDir(fl.rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	if len(rulesYAML) == 0 {
		return nil, fmt.Errorf("no .yml rule files in %s", fl.rulesDir)
	}
	compiled, err := sigmaeval.Load(rulesYAML)
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}
	logger.Info("rules loaded", "count", len(compiled))

	al, alErr := loadAllowlist(fl.allowlistPath)
	if alErr != nil {
		logger.Warn("allowlist load failed; engine runs with nothing trusted (expect noise)",
			"path", fl.allowlistPath, "err", alErr)
		al = nil
	}
	// Inject the Tier-2 (hash_gated_path) signature verifier. On Windows this is
	// native WinVerifyTrust; on non-Windows (CI/dev) the stub fails closed. Must
	// be set before the first Evaluate so the lazy cache sees the verifier.
	if al != nil {
		al.SetSigVerifier(sigverify.IsSignedBy)
	}
	eng, err := rules.New(compiled, al, st)
	if err != nil {
		return nil, fmt.Errorf("engine: %w", err)
	}
	return eng, nil
}

func buildIngester(fl *flags, logger *slog.Logger) (ingest.Ingester, error) {
	if fl.mock {
		logger.Info("using MOCK ingester", "events", fl.mockEvents)
		return mock.New(makeMockEvents(fl.mockEvents)...), nil
	}
	// Experimental: the native EvtSubscribe binding (currently fails with
	// ERROR_INVALID_PARAMETER; kept for future debugging). Default is the
	// PowerShell Get-WinEvent poller, which is proven to read the channel.
	if fl.sysmonNative {
		logger.Warn("using EXPERIMENTAL native EvtSubscribe ingester (known broken)")
		return ingest.NewSysmonRTNative(fl.sysmonChannel, fl.sysmonQuery, logger)
	}
	return ingest.NewSysmonRT(fl.sysmonChannel, fl.sysmonQuery, logger)
}

// loadRulesDir concatenates every *.yml/*.yaml file in dir (sorted) into one
// multi-document YAML blob the Sigma loader can parse.
func loadRulesDir(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
		// Ensure the file ends with a newline, then a YAML document separator
		// (---) before the next file's content. Without this, concatenating two
		// multi-doc files merges the last doc of one with the first of the next
		// into a single mapping with duplicate keys (the yaml.v3 loader sees
		// them as one document). Each file is itself a valid multi-doc stream;
		// the inter-file separator keeps that property across concatenation.
		if len(b) > 0 && b[len(b)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, "---\n"...)
	}
	return out, nil
}

// loadAllowlist returns nil (no error) if the file is absent — the engine
// treats a nil Allowlist as "nothing trusted", which is noisy but safe.
func loadAllowlist(path string) (*allowlist.Allowlist, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("allowlist %s: not found", path)
		}
		return nil, err
	}
	return allowlist.Load(path)
}

// makeMockEvents returns a small canned stream for smoke-testing (-mock):
// one incident vector (so the log visibly shows a HIT once an engine is wired)
// plus benign traffic.
func makeMockEvents(n int) []event.Event {
	out := make([]event.Event, 0, n)
	out = append(out, event.Event{
		EID: 1, Image: `C:\Windows\System32\conhost.exe`,
		CmdLine: `conhost.exe --headless powershell -ep bypass -file "C:\ProgramData\test.ps1"`,
	})
	for i := 1; i < n; i++ {
		out = append(out, event.Event{EID: 1, Image: `C:\Windows\System32\cmd.exe`, CmdLine: `cmd /c echo hi`})
	}
	return out
}

// defaultMutexName derives a per-user global mutex name from the current OS user,
// so no username is hardcoded in source. Falls back to a generic name if the user
// can't be resolved. Strips any DOMAIN\ prefix to keep the mutex name flat.
// exeDir returns the directory of the running executable. Returns "" on error
// (callers fall back to CWD-relative behavior — fine for dev/test where the exe
// sits next to its data).
func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(p)
}

// resolveExeRelative makes each path flag absolute relative to the EXE
// directory if it isn't already absolute. This is what makes the app work when
// launched by Task Scheduler (CWD = system32). Explicit absolute CLI overrides
// pass through unchanged; relative overrides become exe-relative.
func resolveExeRelative(fl *flags) {
	resolve := func(p *string) {
		if *p == "" || filepath.IsAbs(*p) {
			return
		}
		if dir := exeDir(); dir != "" {
			*p = filepath.Join(dir, *p)
		}
	}
	resolve(&fl.rulesDir)
	resolve(&fl.allowlistPath)
	resolve(&fl.statePath)
	resolve(&fl.logPath)
	resolve(&fl.heartbeatPath)
	resolve(&fl.alertsPath)
	resolve(&fl.baselineClean)
	// The snapshot vault and Sysmon archive dir are paths too: left relative,
	// a Task Scheduler launch (CWD = system32) would create/read them under
	// system32 — same failure class resolveExeRelative exists to prevent for
	// every other path flag.
	resolve(&fl.snapshotDir)
	resolve(&fl.sysmonArchiveDir)
}

func defaultMutexName() string {
	name := "sentinel"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
		if i := strings.LastIndexByte(name, '\\'); i >= 0 {
			name = name[i+1:]
		}
	}
	return `Global\Sentinel-Running-` + name
}
