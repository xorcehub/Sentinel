package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// startRun launches the worker and returns a stop func that closes (drains)
// and waits. Mirrors how main.go will wire it.
func startRun(t *testing.T, s *Snapshotter) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	// Graceful drain order: Close the request channel so Run's range drains
	// every pending request and returns, THEN release ctx. If cancel() raced
	// ahead, Run's select could hit ctx.Done first and skip the drain —
	// stranding wg.Add counts and hanging any later Wait().
	return func() {
		s.Close()
		<-done
		cancel()
	}
}

// soleCaptureDir returns the single capture subdir in the vault, failing if
// there isn't exactly one.
func soleCaptureDir(t *testing.T, vault string) string {
	t.Helper()
	entries, err := os.ReadDir(vault)
	if err != nil {
		t.Fatalf("ReadDir vault: %v", err)
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	if len(dirs) != 1 {
		t.Fatalf("expected 1 capture dir, got %d", len(dirs))
	}
	return filepath.Join(vault, dirs[0].Name())
}

func readManifest(t *testing.T, capDir string) manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(capDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	return m
}

// TestCaptureOK is the happy path: a real file is copied to the vault with the
// correct content, sha256, size, and manifest status "ok".
func TestCaptureOK(t *testing.T) {
	vault := t.TempDir()
	src := filepath.Join(t.TempDir(), "ps-script-deadbeef.ps1")
	content := []byte("Write-Host 'hello from cursor'\nexit 0\n")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	wantSHA := sha256.Sum256(content)

	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startRun(t, s)

	s.Submit(Request{
		Path:        src,
		RecordID:    346592,
		Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ParentImage: `C:\Users\jurij\AppData\Local\Programs\cursor\cursor.exe`,
		CmdLine:     `powershell -ep bypass -File ` + src,
		User:        `ACME\jurij`,
		Time:        time.Now(),
	})
	s.Wait()
	stop()

	capDir := soleCaptureDir(t, vault)

	// content matches the source exactly.
	got, err := os.ReadFile(filepath.Join(capDir, "content"))
	if err != nil {
		t.Fatalf("read content: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch:\n got %q\nwant %q", got, content)
	}

	m := readManifest(t, capDir)
	if m.Status != "ok" {
		t.Errorf("status = %q, want ok", m.Status)
	}
	if m.Size != int64(len(content)) {
		t.Errorf("size = %d, want %d", m.Size, len(content))
	}
	if m.SHA256 != hex.EncodeToString(wantSHA[:]) {
		t.Errorf("sha256 = %q, want %q", m.SHA256, hex.EncodeToString(wantSHA[:]))
	}
	if m.RecordID != 346592 {
		t.Errorf("record_id = %d, want 346592", m.RecordID)
	}
	if m.CreatingImage == "" || m.ParentImage == "" || m.CommandLine == "" || m.User == "" {
		t.Errorf("manifest missing event context fields: %+v", m)
	}
	if m.CapturedPath != src {
		t.Errorf("captured_path = %q, want %q", m.CapturedPath, src)
	}
	if s.Captured() != 1 || s.LostRace() != 0 {
		t.Errorf("counters: captured=%d lostRace=%d, want 1/0", s.Captured(), s.LostRace())
	}
}

// TestCaptureLostRace feeds a path that doesn't exist (already deleted — the
// Cursor create-and-delete case). The manifest MUST still be written with
// status "lost-race", no content file, and the lostRace counter increments.
func TestCaptureLostRace(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startRun(t, s)

	s.Submit(Request{
		Path:     filepath.Join(t.TempDir(), "already-deleted.ps1"),
		RecordID: 1,
	})
	s.Wait()
	stop()

	capDir := soleCaptureDir(t, vault)
	m := readManifest(t, capDir)
	if m.Status != "lost-race" {
		t.Errorf("status = %q, want lost-race", m.Status)
	}
	// no content file for a lost race
	if _, err := os.Stat(filepath.Join(capDir, "content")); !os.IsNotExist(err) {
		t.Errorf("lost-race should not write a content file; stat err=%v", err)
	}
	if s.LostRace() != 1 || s.Captured() != 0 {
		t.Errorf("counters: captured=%d lostRace=%d, want 0/1", s.Captured(), s.LostRace())
	}
}

// TestCaptureTruncated feeds a file larger than perFileMax and asserts the copy
// stops at the cap and the manifest status is "truncated".
func TestCaptureTruncated(t *testing.T) {
	vault := t.TempDir()
	src := filepath.Join(t.TempDir(), "big.bin")
	// 4 KB content, 1 KB cap.
	content := make([]byte, 4096)
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(vault, 1, 0, nil) // 1 KB per-file cap
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startRun(t, s)
	s.Submit(Request{Path: src, RecordID: 7})
	s.Wait()
	stop()

	capDir := soleCaptureDir(t, vault)
	got, err := os.ReadFile(filepath.Join(capDir, "content"))
	if err != nil {
		t.Fatalf("read content: %v", err)
	}
	if len(got) != 1024 {
		t.Errorf("truncated content size = %d, want 1024", len(got))
	}
	m := readManifest(t, capDir)
	if m.Status != "truncated" {
		t.Errorf("status = %q, want truncated", m.Status)
	}
}

// TestCaptureExactlyAtCap is the boundary: file size == perFileMax. The
// truncation probe reads 0 extra bytes, so status must be "ok" (we got the
// whole file), NOT "truncated".
func TestCaptureExactlyAtCap(t *testing.T) {
	vault := t.TempDir()
	src := filepath.Join(t.TempDir(), "exact.bin")
	content := make([]byte, 1024) // exactly the 1KB cap
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(vault, 1, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startRun(t, s)
	s.Submit(Request{Path: src, RecordID: 9})
	s.Wait()
	stop()

	m := readManifest(t, soleCaptureDir(t, vault))
	if m.Status != "ok" {
		t.Errorf("file exactly at cap should be ok, not %q", m.Status)
	}
}

// TestEviction fills the vault past totalMax and asserts the oldest captures
// are removed to stay under the cap.
func TestEviction(t *testing.T) {
	vault := t.TempDir()
	// totalMax = 1 MB, captures = 600 KB each. Eviction runs PRE-write (make
	// room before adding), so the vault can transiently overshoot by one
	// capture. With 600 KB captures, 2 of them (1.17 MB) already exceed the 1 MB
	// cap — so the 3rd capture's pre-write eviction fires and removes the
	// oldest, leaving rec2 + rec3. (With 500 KB captures the test would be
	// wrong: 2×500 KB = 976 KB < 1 MB, so no pre-write eviction would trigger.)
	s, err := New(vault, 0, 1, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startRun(t, s)

	writeAndSubmit := func(rec uint64) {
		src := filepath.Join(t.TempDir(), "cap.bin")
		content := make([]byte, 600*1024)
		if err := os.WriteFile(src, content, 0o600); err != nil {
			t.Fatal(err)
		}
		s.Submit(Request{Path: src, RecordID: rec})
		s.Wait()
		// gap so capture-dir mtimes differ (eviction is oldest-mtime first);
		// 50 ms is safely above Windows' ~15 ms dir-mtime resolution.
		time.Sleep(50 * time.Millisecond)
	}
	writeAndSubmit(1)
	writeAndSubmit(2)
	writeAndSubmit(3)
	stop()

	entries, err := os.ReadDir(vault)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	// 3 captures of 600KB each. Pre-write eviction on the 3rd removed the
	// oldest (rec 1), leaving rec2 + rec3 (~1.17 MB — one-capture overshoot
	// above the 1 MB cap, which is the documented transient for pre-write
	// eviction).
	if len(dirs) != 2 {
		t.Errorf("expected 2 capture dirs after eviction, got %d", len(dirs))
	}
	// the surviving dirs should be rec 2 and rec 3 (rec 1 evicted as oldest)
	for _, d := range dirs {
		m := readManifest(t, filepath.Join(vault, d.Name()))
		if m.RecordID == 1 {
			t.Errorf("oldest capture (rec 1) should have been evicted, but manifest exists")
		}
	}
}

// TestSubmitDropsWhenBufferFull asserts Submit is non-blocking: with the
// worker NOT draining, filling the 256-slot buffer then submitting one more
// returns false and increments dropped — the guarantee that a capture flood
// never blocks the detection goroutine.
func TestSubmitDropsWhenBufferFull(t *testing.T) {
	vault := t.TempDir()
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// do NOT start Run — nothing drains the buffer.
	ghost := filepath.Join(t.TempDir(), "ghost.ps1")
	for i := 0; i < 256; i++ {
		if !s.Submit(Request{Path: ghost, RecordID: uint64(i)}) {
			t.Fatalf("submit %d should succeed (buffer not full yet)", i)
		}
	}
	// 257th: buffer full -> drop.
	if s.Submit(Request{Path: ghost, RecordID: 999}) {
		t.Error("submit past buffer capacity should return false (dropped)")
	}
	if s.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1", s.Dropped())
	}
	// drain so the test doesn't leak pending wg Adds. stop() closes the request
	// channel and blocks until Run has drained every queued request and
	// returned — so wg is 0 by the time stop() returns (no separate Wait needed).
	stop := startRun(t, s)
	stop()
}

// TestNewRejectsEmptyDir asserts config validation.
func TestNewRejectsEmptyDir(t *testing.T) {
	if _, err := New("", 0, 0, nil); err == nil {
		t.Error("New with empty dir should error")
	}
}

// TestCaptureNoExtension asserts the content file has NO extension — it must
// not be directly executable from the vault (a safety property).
func TestCaptureNoExtension(t *testing.T) {
	vault := t.TempDir()
	src := filepath.Join(t.TempDir(), "evil.ps1")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(vault, 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := startRun(t, s)
	s.Submit(Request{Path: src, RecordID: 1})
	s.Wait()
	stop()

	capDir := soleCaptureDir(t, vault)
	// the content file must be named "content" with no extension
	if _, err := os.Stat(filepath.Join(capDir, "content")); err != nil {
		t.Errorf("expected content file with no extension: %v", err)
	}
	// and there must be no .ps1 / .exe / .bat in the capture dir
	entries, _ := os.ReadDir(capDir)
	for _, e := range entries {
		switch filepath.Ext(e.Name()) {
		case ".ps1", ".exe", ".bat", ".cmd", ".vbs", ".js":
			t.Errorf("capture dir contains an executable-script file %q — vault must be non-executable", e.Name())
		}
	}
}

func TestFindArchived(t *testing.T) {
	dir := t.TempDir()
	// Simulate Sysmon's archive directory structure:
	//   <archiveDir>/C/Users/.../Temp/ps-script-abc.ps1
	nested := filepath.Join(dir, "C", "Users", "test", "Temp")
	os.MkdirAll(nested, 0o755)
	target := filepath.Join(nested, "ps-script-abc123.ps1")
	os.WriteFile(target, []byte("test"), 0o644)

	// Should find by base filename
	got := FindArchived(dir, "ps-script-abc123.ps1")
	if got != target {
		t.Errorf("FindArchived: expected %q, got %q", target, got)
	}

	// Should find by partial name (substring match)
	got = FindArchived(dir, "ps-script-abc")
	if got != target {
		t.Errorf("FindArchived partial: expected %q, got %q", target, got)
	}

	// Should return "" for non-existent file
	got = FindArchived(dir, "nonexistent.ps1")
	if got != "" {
		t.Errorf("FindArchived non-existent: expected empty, got %q", got)
	}

	// Should return "" for empty inputs
	if FindArchived("", "foo") != "" {
		t.Error("empty dir should return empty")
	}
	if FindArchived(dir, "") != "" {
		t.Error("empty name should return empty")
	}
}

func TestNewestArchiveFile(t *testing.T) {
	dir := t.TempDir()
	// Create files with distinct mtimes. Newest should win.
	old1 := filepath.Join(dir, "old1.ps1")
	newer := filepath.Join(dir, "newer.ps1")
	newest := filepath.Join(dir, "newest.ps1")
	os.WriteFile(old1, []byte("a"), 0o644)
	os.WriteFile(newer, []byte("b"), 0o644)
	os.WriteFile(newest, []byte("c"), 0o644)
	// Force mtime ordering (create order may not guarantee mtime).
	os.Chtimes(old1, time.Now().Add(-1*time.Hour), time.Now().Add(-1*time.Hour))
	os.Chtimes(newer, time.Now().Add(-1*time.Minute), time.Now().Add(-1*time.Minute))
	os.Chtimes(newest, time.Now(), time.Now())

	got := NewestArchiveFile(dir)
	if got != newest {
		t.Errorf("NewestArchiveFile: expected %q, got %q", newest, got)
	}
	if NewestArchiveFile("") != "" {
		t.Error("empty dir should return empty")
	}
}

// Submit after Close must be a no-op (return false), never panic on a send to
// the closed channel — the doc has always claimed this; now the code honors it.
func TestSubmitAfterCloseIsNoop(t *testing.T) {
	s, err := New(t.TempDir(), 0, 0, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan struct{})
	go func() { s.Run(context.Background()); close(done) }()
	s.Close()
	<-done
	if s.Submit(Request{Path: `C:\does\not\exist`}) {
		t.Fatal("Submit after Close returned true; want false (no-op)")
	}
}

// Regression for the send-then-Add WaitGroup race: with wg.Add AFTER the
// channel send, a worker that received the request and finished capture() (a
// lost-race capture is just a handful of syscalls) could hit the deferred
// wg.Done() on a zero counter -> "sync: negative WaitGroup counter" panic.
// Hammer Submit/Run/Wait concurrently; run under -race in CI.
func TestSubmitWaitGroupOrderUnderLoad(t *testing.T) {
	s, err := New(t.TempDir(), 1, 0, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	go s.Run(context.Background())
	lostDir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.Submit(Request{
					Path:     filepath.Join(lostDir, "gone.txt"), // always lost-race: fast capture path
					RecordID: uint64(n*1000 + j),
				})
			}
		}(i)
	}
	wg.Wait()
	// Shutdown MUST be Close-first: cancelling before drain would strand queued
	// requests with outstanding wg reservations and hang Wait below.
	s.Close()
	s.Wait() // panics (negative counter) if Done can outrun Add
}
