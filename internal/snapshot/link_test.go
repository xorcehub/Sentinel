package snapshot

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests pin the A.4 hid back-link: a capture's manifest gets the alert's
// hid stamped into it when a later hit's cmdline references the captured path.
// This is the forensics pivot — from any EXEC-001 alert you can jump straight
// to the captured script contents in the vault.

func startWorker(t *testing.T, s *Snapshotter) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	return func() { s.Close(); <-done; cancel() }
}

func readManifestFile(t *testing.T, capDir string) manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(capDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

// TestLinkHitBackLinksManifest is the happy path: capture a real file, then
// call LinkHit with a cmdline that references it. The manifest's linked_hid
// must be set to the hit's hid.
func TestLinkHitBackLinksManifest(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startWorker(t, s)

	src := filepath.Join(t.TempDir(), "ps-script-deadbeef.ps1")
	content := []byte("Write-Host 'captured by sentinel'\n")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	s.Submit(Request{Path: src, RecordID: 100})
	s.Wait()

	// The capture is indexed. Now fire a hit whose cmdline references src.
	hid := "R-20260714-ABC12-000001"
	cmdline := "powershell.exe -ExecutionPolicy Bypass -File " + src
	n := s.LinkHit(hid, cmdline, "")
	stop()

	if n != 1 {
		t.Fatalf("LinkHit returned %d, want 1 (one manifest should be updated)", n)
	}

	// Find the capture dir and verify the manifest.
	entries, _ := os.ReadDir(vault)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m := readManifestFile(t, filepath.Join(vault, e.Name()))
		if m.LinkedHID != hid {
			t.Errorf("linked_hid = %q, want %q", m.LinkedHID, hid)
		}
		if m.Status != "ok" {
			t.Errorf("status = %q, want ok", m.Status)
		}
	}
}

// TestLinkHitMatchesCaseInsensitive confirms the cmdline/path matching is
// case-insensitive (Sysmon cmdline casing differs from TargetFile casing).
func TestLinkHitMatchesCaseInsensitive(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startWorker(t, s)

	// Capture with a mixed-case path.
	src := filepath.Join(t.TempDir(), "Ps-Script-DeadBeef.ps1")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Submit(Request{Path: src, RecordID: 1})
	s.Wait()

	// Hit's cmdline has DIFFERENT casing for the path.
	cmdline := "powershell.exe -ep bypass -File " + filepath.Join(filepath.Dir(src), "ps-Script-deadbeef.PS1")
	if n := s.LinkHit("R-HID-001", cmdline, ""); n != 1 {
		t.Errorf("case-insensitive match: LinkHit = %d, want 1", n)
	}
	stop()
}

// TestLinkHitNoMatch asserts a hit whose cmdline doesn't reference any captured
// path returns 0 and doesn't touch any manifest.
func TestLinkHitNoMatch(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startWorker(t, s)

	src := filepath.Join(t.TempDir(), "ps-script-real.ps1")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Submit(Request{Path: src, RecordID: 1})
	s.Wait()

	// Unrelated cmdline — no captured path referenced.
	if n := s.LinkHit("R-HID-002", "cmd.exe /c dir", ""); n != 0 {
		t.Errorf("unrelated cmdline: LinkHit = %d, want 0", n)
	}
	stop()

	// Verify no manifest has a linked_hid.
	entries, _ := os.ReadDir(vault)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m := readManifestFile(t, filepath.Join(vault, e.Name()))
		if m.LinkedHID != "" {
			t.Errorf("unrelated hit should not set linked_hid; got %q", m.LinkedHID)
		}
	}
}

// TestLinkHitTargetFileMatch asserts the EID-11 hit path: when a hit's
// TargetFile IS the captured path (e.g. PERSIST-004 fires on a Startup-folder
// file write that was also captured), the back-link fires via exact match.
func TestLinkHitTargetFileMatch(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startWorker(t, s)

	src := filepath.Join(t.TempDir(), "backdoor.lnk")
	if err := os.WriteFile(src, []byte("shortcut"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Submit(Request{Path: src, RecordID: 42})
	s.Wait()

	// Hit has no cmdline, but TargetFile matches exactly.
	if n := s.LinkHit("R-HID-003", "", src); n != 1 {
		t.Errorf("target-file exact match: LinkHit = %d, want 1", n)
	}
	stop()
}

// TestLinkHitFirstWriteWins asserts that if two hits reference the same capture
// (e.g. EXEC-001 + PERSIST-001 both fire on the same event), only the FIRST
// hid is stamped — the second is silently skipped (first-write-wins). Both hids
// are findable in ALERTS.log by searching for the captured_path.
func TestLinkHitFirstWriteWins(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startWorker(t, s)

	src := filepath.Join(t.TempDir(), "ps-script-dual.ps1")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Submit(Request{Path: src, RecordID: 1})
	s.Wait()

	cmdline := "powershell.exe -ep bypass -File " + src
	first := "R-20260714-FIRST1-000001"
	second := "R-20260714-SECOND-000002"

	if n := s.LinkHit(first, cmdline, ""); n != 1 {
		t.Fatalf("first LinkHit = %d, want 1", n)
	}
	if n := s.LinkHit(second, cmdline, ""); n != 0 {
		t.Errorf("second LinkHit = %d, want 0 (first-write-wins)", n)
	}
	stop()

	// The manifest should have the FIRST hid, not the second.
	entries, _ := os.ReadDir(vault)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m := readManifestFile(t, filepath.Join(vault, e.Name()))
		if m.LinkedHID != first {
			t.Errorf("linked_hid = %q, want %q (first write should win)", m.LinkedHID, first)
		}
	}
}

// TestLinkHitLostRaceStillLinks asserts that a lost-race capture (file gone
// before copy) is still indexed and back-linkable. The operator needs to know
// "we saw the create but couldn't copy; here's the alert that references it."
func TestLinkHitLostRaceStillLinks(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startWorker(t, s)

	// Non-existent path -> lost race.
	ghost := filepath.Join(t.TempDir(), "ps-script-ghost.ps1")
	s.Submit(Request{Path: ghost, RecordID: 7})
	s.Wait()

	if s.LostRace() != 1 {
		t.Fatalf("expected 1 lost race, got %d", s.LostRace())
	}

	// The lost-race capture is still indexed. A hit referencing it should
	// back-link — the manifest (status=lost-race) gets the hid.
	cmdline := "powershell.exe -ep bypass -File " + ghost
	if n := s.LinkHit("R-HID-LOST-001", cmdline, ""); n != 1 {
		t.Errorf("lost-race back-link: LinkHit = %d, want 1", n)
	}
	stop()
}

// TestLinkHitEmptyHid asserts a no-op on empty hid (defensive).
func TestLinkHitEmptyHid(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if n := s.LinkHit("", "some cmdline", ""); n != 0 {
		t.Errorf("empty hid: LinkHit = %d, want 0", n)
	}
}

// TestLinkHitNoCaptures asserts LinkHit is a no-op when nothing has been
// captured yet (empty index).
func TestLinkHitNoCaptures(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if n := s.LinkHit("R-HID-004", "powershell -File C:\\Temp\\ps-script.ps1", ""); n != 0 {
		t.Errorf("empty index: LinkHit = %d, want 0", n)
	}
}

// TestIndexExpiresAfterTTL asserts that a captured path falls out of the index
// after linkTTL, so a late hit can't back-link to a stale capture. This keeps
// the index bounded without manual cleanup.
func TestIndexExpiresAfterTTL(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startWorker(t, s)

	src := filepath.Join(t.TempDir(), "ps-script-ttl.ps1")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Submit(Request{Path: src, RecordID: 1})
	s.Wait()

	// Manually age the index entry past linkTTL.
	s.linkMu.Lock()
	for k := range s.linkAge {
		s.linkAge[k] = time.Now().Add(-(linkTTL + time.Second))
	}
	s.linkMu.Unlock()

	// Trigger a TTL eviction by indexing a new capture (which runs the lazy
	// eviction loop). Then the old path should be gone from the index.
	fresh := filepath.Join(t.TempDir(), "fresh.ps1")
	if err := os.WriteFile(fresh, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Submit(Request{Path: fresh, RecordID: 2})
	s.Wait()

	// The old (expired) path should no longer back-link.
	cmdline := "powershell.exe -ep bypass -File " + src
	if n := s.LinkHit("R-HID-EXPIRED", cmdline, ""); n != 0 {
		t.Errorf("expired capture should not back-link; LinkHit = %d, want 0", n)
	}
	// But the fresh one should.
	cmdline2 := "powershell.exe -ep bypass -File " + fresh
	if n := s.LinkHit("R-HID-FRESH", cmdline2, ""); n != 1 {
		t.Errorf("fresh capture should back-link; LinkHit = %d, want 1", n)
	}
	stop()
}
