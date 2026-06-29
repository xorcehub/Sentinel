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
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"

	"sentinel/internal/alert"
	"sentinel/internal/allowlist"
	"sentinel/internal/app"
	"sentinel/internal/event"
	"sentinel/internal/ingest"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/proc"
	"sentinel/internal/rules"
	"sentinel/internal/selftest"
	"sentinel/internal/sigmaeval"
	"sentinel/internal/state"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: %v\n", err)
		os.Exit(1)
	}
}

type flags struct {
	rulesDir      string
	allowlistPath string
	statePath     string
	logPath       string
	heartbeatPath string
	alertsPath    string
	debug         bool
	mock          bool
	mockEvents    int
	raw           bool
	mutexName     string
	sysmonChannel string
	sysmonQuery   string
	sysmonNative  bool
	selfTest      bool
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
	f.BoolVar(&out.mock, "mock", false, "use the mock ingester (testing / smoke)")
	f.IntVar(&out.mockEvents, "mock-events", 5, "number of mock events to emit (with -mock)")
	f.BoolVar(&out.raw, "raw", false, "raw passthrough: log events, do not run the engine")
	f.StringVar(&out.mutexName, "mutex", "", "single-instance mutex name (default: Global\\Sentinel-Running-<current-user>)")
	f.StringVar(&out.sysmonChannel, "sysmon-channel", "Microsoft-Windows-Sysmon/Operational", "Sysmon event channel")
	f.StringVar(&out.sysmonQuery, "sysmon-query", "", "override the Sysmon XPath filter (diagnostic; use \"*\" to subscribe to all events)")
	f.BoolVar(&out.sysmonNative, "sysmon-native", false, "use the experimental native EvtSubscribe ingester (known broken: ERROR_INVALID_PARAMETER)")
	f.BoolVar(&out.selfTest, "self-test", false, "run the incident-coverage regression against the catalog and exit")
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

	a, err := app.New(app.Options{
		Logger:        logger,
		Ingester:      ing,
		Engine:        eng,
		HeartbeatPath: fl.heartbeatPath,
		Dispatcher:    disp,
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
	alerters := []alert.Alerter{logAlerter, alert.NewPopupAlerter(logger), alert.NewEventLogAlerter("Sentinel", logger), alert.NewToastAlerter(logger)}
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
	// Best-effort stdout (works for console builds; silent under windowsgui).
	fmt.Print(report)

	// Mandatory file write - the channel that works under the windowsgui build.
	reportPath := filepath.Join(exeDir(), "self-test.txt")
	if exeDir() == "" {
		reportPath = "self-test.txt" // fallback to CWD if exe dir unknown
	}
	if werr := os.WriteFile(reportPath, []byte(report), 0o644); werr != nil {
		return fmt.Errorf("self-test: write report %s: %w (report below)\n%s", reportPath, werr, report)
	}
	// If stdout was usable, the report already printed above; under windowsgui
	// the operator reads self-test.txt. We can't print "see self-test.txt" via
	// stdout (dead handle), so the file IS the contract.

	if !allPassed {
		return fmt.Errorf("self-test FAILED (see %s)", reportPath)
	}
	return nil
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
