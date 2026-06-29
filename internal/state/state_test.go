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
