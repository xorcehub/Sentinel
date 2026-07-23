package state

import (
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *State {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRecordIDHighWater(t *testing.T) {
	s := openTemp(t)
	if s.MaxRecordID() != 0 {
		t.Fatal("fresh state max should be 0")
	}
	// RT sees event 50 -> not previously seen, mark it.
	if s.SweepSeen(50) {
		t.Error("50 should not be seen on fresh state")
	}
	s.MarkSeen(50)
	if s.MaxRecordID() != 50 {
		t.Errorf("max=%d want 50", s.MaxRecordID())
	}
	// sweep of same event -> seen (skip)
	if !s.SweepSeen(50) {
		t.Error("50 should now be seen")
	}
	// sweep of older event -> also seen
	if !s.SweepSeen(40) {
		t.Error("40 below high-water should be seen")
	}
	// sweep of newer event -> not seen (RT missed it during downtime)
	if s.SweepSeen(60) {
		t.Error("60 above high-water should not yet be seen")
	}
	s.MarkSeen(60)
	// MarkSeen is monotonic: a lower ID never lowers the high-water
	s.MarkSeen(10)
	if s.MaxRecordID() != 60 {
		t.Errorf("max should stay 60, got %d", s.MaxRecordID())
	}
	// RecordID 0 (pseudo-event) never participates
	s.MarkSeen(0)
	if s.MaxRecordID() != 60 {
		t.Errorf("MarkSeen(0) must be a no-op; max=%d", s.MaxRecordID())
	}
}

func TestReAlertWindow(t *testing.T) {
	s := openTemp(t)
	// first alert for this key -> allowed
	if !s.ReAlert("NET-005", "img|127.0.0.1:58172", time.Hour) {
		t.Error("first ReAlert should be allowed")
	}
	// immediate second -> suppressed (within 1h)
	if s.ReAlert("NET-005", "img|127.0.0.1:58172", time.Hour) {
		t.Error("second ReAlert within window should be suppressed")
	}
	// same rule, different target -> allowed (dedup is per target_key)
	if !s.ReAlert("NET-005", "img|127.0.0.1:9999", time.Hour) {
		t.Error("different target_key should be allowed")
	}
	// different rule, same target -> allowed (dedup is per rule)
	if !s.ReAlert("OTHER", "img|127.0.0.1:58172", time.Hour) {
		t.Error("different rule should be allowed")
	}
	// very short window -> second call passes immediately
	if !s.ReAlert("SHORT", "k", 1) {
		t.Fatal("setup")
	}
	time.Sleep(5 * time.Millisecond)
	if !s.ReAlert("SHORT", "k", 1) {
		t.Error("after window elapsed, ReAlert should pass")
	}
}

// default-window fallback when a rule omits dedup (must not panic / zero-window).
func TestReAlertDefaultWindow(t *testing.T) {
	s := openTemp(t)
	if !s.ReAlert("R", "k", 0) { // 0 -> default 15m
		t.Fatal("first allowed")
	}
	if s.ReAlert("R", "k", 0) {
		t.Error("second within default window should be suppressed")
	}
}

// TestReAlertFailsOpenOnStateError pins Sentinel's core invariant: "detection
// is never blinded by suppression." ReAlert drives the engine's dedup branch
// (engine.go: `!ReAlert(...) -> Suppressed{dedup-window}`), so a state-store
// write error MUST NOT suppress a hit. We close the bbolt DB (Update then
// returns ErrDatabaseNotOpen, the documented closed-handle behavior) and
// assert ReAlert returns true (allow the alert) rather than false (suppress).
// Regression guard for the silent-blindness bug where the Update error was
// swallowed and the zero-value `allowed` was returned.
func TestReAlertFailsOpenOnStateError(t *testing.T) {
	s := openTemp(t)
	// Establish a key already in its window: on a healthy store, the second
	// call below would be suppressed (return false). We'll show the error path
	// overrides that.
	if !s.ReAlert("NET-005", "img|127.0.0.1:58172", time.Hour) {
		t.Fatal("precondition: first ReAlert must be allowed")
	}
	s.Close() // force every subsequent Update to error (ErrDatabaseNotOpen)

	// Same key, within window — healthy store returns false (suppressed).
	// Broken store MUST return true: fail open, alert rather than blind.
	if !s.ReAlert("NET-005", "img|127.0.0.1:58172", time.Hour) {
		t.Fatal("ReAlert on a failed state write must fail OPEN (return true); " +
			"returning false would silently suppress a real detection " +
			"(blindness via the dedup path)")
	}
}

// TestMarkSeenLogsOnError confirms a failed high-water write is non-fatal and
// surfaces (no panic, no miss). The worst case for MarkSeen is a duplicate
// alert on the next sweep, never a missed detection. We only assert it doesn't
// panic on a closed store; the log line is a side effect we don't capture.
func TestMarkSeenLogsOnError(t *testing.T) {
	s := openTemp(t)
	s.Close()
	// Must not panic on a broken store; the error is logged and swallowed.
	s.MarkSeen(42)
}

// TestBaselineAlertOnce: the Phase 3d Option-A "alert once" store. A key that
// has not been seen reports not-alerted; after MarkBaselineAlerted it reports
// alerted forever (no time window) until ResetBaselineAlerted clears the set.
// This is the gate that keeps an unaddressed NEW persistence entry from
// re-alerting on every daily scan.
func TestBaselineAlertOnce(t *testing.T) {
	s := openTemp(t)
	key := `HKLM\Software\...\Run\Evil`
	if s.BaselineAlerted(key) {
		t.Error("fresh state: key should not be alerted")
	}
	s.MarkBaselineAlerted(key)
	if !s.BaselineAlerted(key) {
		t.Error("after Mark, key should be alerted")
	}
	// Idempotent + persistent (no window expiry like ReAlert).
	s.MarkBaselineAlerted(key)
	if !s.BaselineAlerted(key) {
		t.Error("second Mark must not clear the alert flag")
	}
	// A different key is independent.
	if s.BaselineAlerted(`HKLM\Other\Key`) {
		t.Error("unrelated key should not be alerted")
	}
}

// TestBaselineAlertReset: re-snapshotting the clean baseline (operator accepted
// the entries) clears the alerted set, so a genuine reappearance of the same
// (location,entry) later fires again instead of being suppressed as stale.
func TestBaselineAlertReset(t *testing.T) {
	s := openTemp(t)
	key := `HKLM\...\Evil`
	s.MarkBaselineAlerted(key)
	if !s.BaselineAlerted(key) {
		t.Fatal("precondition: marked")
	}
	if err := s.ResetBaselineAlerted(); err != nil {
		t.Fatalf("ResetBaselineAlerted: %v", err)
	}
	if s.BaselineAlerted(key) {
		t.Error("after reset, key should no longer be alerted")
	}
	// Reset on an empty set is a no-op (not an error).
	if err := s.ResetBaselineAlerted(); err != nil {
		t.Errorf("reset on empty set should be a no-op, got %v", err)
	}
	// And marking works again after reset (the scan-after-resnapshot path).
	s.MarkBaselineAlerted(key)
	if !s.BaselineAlerted(key) {
		t.Error("re-mark after reset should take effect")
	}
}

// TestBaselineAlertPersistsAcrossOpen: the alerted set must survive a Sentinel
// restart, otherwise a daemon restart would re-alert every unaddressed entry.
// (state.db is the persistence layer; verify by reopening the same file.)
func TestBaselineAlertPersistsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s1.MarkBaselineAlerted(`persisted\key`)
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if !s2.BaselineAlerted(`persisted\key`) {
		t.Error("alerted flag must survive reopen (state.db persistence)")
	}
}
