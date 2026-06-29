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

	"sentinel/internal/allowlist"
	"sentinel/internal/app"
	"sentinel/internal/event"
	"sentinel/internal/ingest"
	"sentinel/internal/ingest/mock"
	"sentinel/internal/proc"
	"sentinel/internal/rules"
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
	debug         bool
	mock          bool
	mockEvents    int
	raw           bool
	mutexName     string
	sysmonChannel string
	sysmonQuery   string
	sysmonNative  bool
}

func parseFlags(args []string) (*flags, *flag.FlagSet) {
	f := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	out := &flags{}
	f.StringVar(&out.rulesDir, "rules", "rules.d", "rules directory (Sigma .yml)")
	f.StringVar(&out.allowlistPath, "allowlist", "config/allowlist.json", "allowlist JSONC")
	f.StringVar(&out.statePath, "state", "state.db", "bbolt state file path")
	f.StringVar(&out.logPath, "log", "sentinel.log", "log file (append)")
	f.StringVar(&out.heartbeatPath, "heartbeat", "heartbeat.log", "heartbeat file")
	f.BoolVar(&out.debug, "debug", true, "debug-level logging")
	f.BoolVar(&out.mock, "mock", false, "use the mock ingester (testing / smoke)")
	f.IntVar(&out.mockEvents, "mock-events", 5, "number of mock events to emit (with -mock)")
	f.BoolVar(&out.raw, "raw", false, "raw passthrough: log events, do not run the engine")
	f.StringVar(&out.mutexName, "mutex", "", "single-instance mutex name (default: Global\\Sentinel-Running-<current-user>)")
	f.StringVar(&out.sysmonChannel, "sysmon-channel", "Microsoft-Windows-Sysmon/Operational", "Sysmon event channel")
	f.StringVar(&out.sysmonQuery, "sysmon-query", "", "override the Sysmon XPath filter (diagnostic; use \"*\" to subscribe to all events)")
	f.BoolVar(&out.sysmonNative, "sysmon-native", false, "use the experimental native EvtSubscribe ingester (known broken: ERROR_INVALID_PARAMETER)")
	return out, f
}

func run(args []string) error {
	fl, fs := parseFlags(args)
	if err := fs.Parse(args); err != nil {
		return err
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

	a, err := app.New(app.Options{
		Logger:        logger,
		Ingester:      ing,
		Engine:        eng,
		HeartbeatPath: fl.heartbeatPath,
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
		// ensure documents are separated if the file didn't end with one
		if len(b) > 0 && b[len(b)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, '\n')
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
