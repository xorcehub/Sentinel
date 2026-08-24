package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinel/internal/event"
)

// H1 telemetry-lost check (docs/hardening-plan_2308.md): a stale Sysmon feed
// must produce exactly ONE critical HEALTH-001 hit per stale episode via the
// heartbeat path, re-armed when flow resumes, and never on the shutdown write.
func TestTelemetryStaleFiresHealth001Once(t *testing.T) {
	dir := t.TempDir()
	hits := make(chan event.Hit, 8)
	a, err := New(Options{
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Ingester:                nopIngester{},
		HeartbeatPath:           filepath.Join(dir, "heartbeat.log"),
		TelemetryStaleThreshold: time.Minute, // injectable → testable without waiting 10 real minutes
		OnHit:                   func(h event.Hit) { hits <- h },
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	a.lastSysmonEvent.Store(now.Add(-5 * time.Minute).UnixNano()) // stale

	// First heartbeat: HEALTH-001 must fire, critical.
	a.writeHeartbeat(now, false)
	select {
	case h := <-hits:
		if h.RuleID != "HEALTH-001" || h.Severity != event.SevCritical {
			t.Fatalf("got %s/%s want HEALTH-001/critical", h.RuleID, h.Severity)
		}
	default:
		t.Fatal("stale ingestion did not produce a HEALTH-001 hit")
	}

	// Heartbeat line carries the sysmon= status field.
	b, err := os.ReadFile(a.opts.HeartbeatPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "sysmon=STALE") {
		t.Errorf("heartbeat line missing sysmon=STALE:\n%s", b)
	}

	// Second tick while still stale: alert-once per episode — no re-fire.
	a.writeHeartbeat(now.Add(5*time.Minute), false)
	select {
	case h := <-hits:
		t.Fatalf("HEALTH-001 re-fired within the same stale episode: %s", h.ID)
	default:
	}

	// Flow resumes → latch re-arms; going stale again must fire once more.
	a.handleEvent(event.Event{Source: event.SrcSysmonRT, EID: 1})
	a.lastSysmonEvent.Store(time.Now().Add(-2 * time.Minute).UnixNano())
	a.writeHeartbeat(now.Add(10*time.Minute), false)
	select {
	case <-hits:
	default:
		t.Fatal("HEALTH-001 did not re-arm after flow resumed")
	}

	// Shutdown-path write while stale: no spurious final hit.
	a.lastSysmonEvent.Store(time.Now().Add(-30 * time.Minute).UnixNano())
	a.writeHeartbeat(now.Add(15*time.Minute), true)
	select {
	case h := <-hits:
		t.Fatalf("shutdown write fired a spurious %s", h.RuleID)
	default:
	}
}

// Baseline pseudo-events must NOT count as telemetry flow (they'd mask a dead
// Sysmon channel).
func TestBaselineEventsDoNotCountAsFlow(t *testing.T) {
	a, err := New(Options{
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Ingester:                nopIngester{},
		TelemetryStaleThreshold: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).UnixNano()
	a.lastSysmonEvent.Store(old)
	a.handleEvent(event.Event{Source: event.SrcBaseline, EID: 0})
	if got := a.lastSysmonEvent.Load(); got != old {
		t.Fatalf("baseline event refreshed lastSysmonEvent (would mask dead Sysmon)")
	}
	a.healthAlerted.Store(true) // would only stay latched if flow wasn't seen
	a.handleEvent(event.Event{Source: event.SrcSysmonRT, EID: 1})
	if a.healthAlerted.Load() {
		t.Fatal("sysmon event did not re-arm the health alert")
	}
}

// Negative TelemetryStaleThreshold must DISABLE the check (Options contract):
// never fire HEALTH-001 and always report flowing — not "always fire", which
// was the inverted behavior before the threshold>0 guard.
func TestNegativeThresholdDisablesCheck(t *testing.T) {
	dir := t.TempDir()
	hits := make(chan event.Hit, 4)
	a, err := New(Options{
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Ingester:                nopIngester{},
		HeartbeatPath:           filepath.Join(dir, "heartbeat.log"),
		TelemetryStaleThreshold: -time.Minute, // documented as disable
		OnHit:                   func(h event.Hit) { hits <- h },
	})
	if err != nil {
		t.Fatal(err)
	}
	a.lastSysmonEvent.Store(time.Now().Add(-time.Hour).UnixNano()) // very stale
	a.writeHeartbeat(time.Now(), false)
	select {
	case h := <-hits:
		t.Fatalf("negative threshold fired %s — disable is inverted", h.RuleID)
	default:
	}
	b, err := os.ReadFile(a.opts.HeartbeatPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sysmon=STALE") {
		t.Errorf("disabled check reported STALE:\n%s", b)
	}
}

// Startup grace must be bounded: New() seeds lastSysmonEvent with process
// start, so a Sysmon channel that was already dead BEFORE Sentinel started
// still accrues staleness and fires HEALTH-001 instead of reporting flowing
// forever.
func TestStartupGraceIsBounded(t *testing.T) {
	dir := t.TempDir()
	hits := make(chan event.Hit, 4)
	a, err := New(Options{
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Ingester:                nopIngester{},
		HeartbeatPath:           filepath.Join(dir, "heartbeat.log"),
		TelemetryStaleThreshold: time.Minute,
		OnHit:                   func(h event.Hit) { hits <- h },
	})
	if err != nil {
		t.Fatal(err)
	}
	seeded := time.Unix(0, a.lastSysmonEvent.Load())
	if time.Since(seeded) > time.Minute {
		t.Fatalf("New() did not seed lastSysmonEvent with process start: %v", seeded)
	}
	// Simulate startup with an already-dead channel: enough wall time passes.
	a.writeHeartbeat(seeded.Add(2*time.Minute), false)
	select {
	case h := <-hits:
		if h.RuleID != "HEALTH-001" {
			t.Fatalf("got %s want HEALTH-001", h.RuleID)
		}
	default:
		t.Fatal("already-dead Sysmon at startup never fired HEALTH-001")
	}
}

// nopIngester satisfies ingest.Ingester for tests that never call Run.
type nopIngester struct{}

func (nopIngester) Start(ctx context.Context) (<-chan event.Event, error) {
	ch := make(chan event.Event)
	close(ch)
	return ch, nil
}
