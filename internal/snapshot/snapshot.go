// Package snapshot copies files that match the allowlist's file_capture
// patterns (EID 11 FileCreate) into a forensic vault, off the detection
// goroutine. It exists for the create-and-delete dropper pattern: Cursor
// spawns `powershell -ep bypass -File <TEMP>\ps-script-<guid>.ps1` and deletes
// the script the instant it exits, so without a snapshot its contents are
// never inspectable.
//
// Detection decoupling: the snapshotter is purely additive. It reads no rule
// input and consults no except operator; Submit is non-blocking (default-drop
// on a full buffer) and runs on its own goroutine, so it can neither block nor
// alter Evaluate. A capture that fails (file already deleted) writes a
// "lost-race" manifest so the operator knows the create was seen — Sysmon
// FileDelete archiving (Layer B) is the guaranteed backstop for those.
//
// Vault layout (one dir per captured file):
//
//	<vault>/<YYYYMMDD-HHMMSS.fff>_<rec>_<nonce>/
//	    content          the copy, NO extension (can't be executed)
//	    manifest.json    {record_id, captured_path, creating_image, parent,
//	                      commandline, user, time, sha256, size, status,
//	                      linked_hid}
//
// status is "ok" (full copy), "truncated" (hit the per-file cap), or
// "lost-race" (file gone before we could open it — manifest only, no content).
// linked_hid is filled later by the app layer when an alert's cmdline names the
// captured path (A.4).
package snapshot

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinel/internal/pathnorm"
)

// Request describes one file to snapshot. Populated from the EID 11 event.
type Request struct {
	Path        string // the file to copy (ev.TargetFile, or the Sysmon archive path for EID 23)
	RecordID    uint64 // source Sysmon EventRecordID (for pivoting back to Event Viewer)
	Image       string // creating process image
	ParentImage string // parent process image
	CmdLine     string // creating process command line
	User        string // user context
	Time        time.Time
	IsArchive   bool // true when Path is a Sysmon archive copy (EID 23), not the original
}

// Snapshotter is the vault writer. Construct with New; drive with Run; stop
// with Close (graceful drain) or context cancellation (immediate). Submit is
// safe for concurrent use and never blocks.
type Snapshotter struct {
	dir        string // vault root (absolute)
	perFileMax int64  // max bytes copied per file; 0 = unlimited
	totalMax   int64  // max total vault bytes; 0 = unlimited (no eviction)
	log        *slog.Logger

	in       chan Request   // buffered request queue
	wg       sync.WaitGroup // tracks submitted-but-not-yet-processed requests
	closedMu sync.Mutex
	closed   bool

	captured atomic.Uint64 // successfully copied (ok or truncated)
	lostRace atomic.Uint64 // file gone before copy
	dropped  atomic.Uint64 // buffer full; request not queued

	// link indexes captured-path -> capture-dir so a later alert whose cmdline
	// references that path can back-link its hid into the manifest (A.4).
	// Bounded by linkMax entries; entries expire after linkTTL. In-memory only
	// (lost on restart — manifests persist on disk, correlatable via record_id).
	linkMu  sync.Mutex
	link    map[string]string    // normalized captured path -> capDir
	linkAge map[string]time.Time // normalized captured path -> indexed-at
}

// New creates a Snapshotter writing to dir. perFileMaxKB caps each file's copy
// (0 = no cap); totalMaxMB caps the vault size, evicting oldest captures when
// exceeded (0 = no eviction). The vault dir is created if missing.
func New(dir string, perFileMaxKB, totalMaxMB int, log *slog.Logger) (*Snapshotter, error) {
	if dir == "" {
		return nil, errors.New("snapshot: dir is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("snapshot: resolve dir %s: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("snapshot: create vault %s: %w", abs, err)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Snapshotter{
		dir:        abs,
		perFileMax: int64(perFileMaxKB) * 1024,
		totalMax:   int64(totalMaxMB) * 1024 * 1024,
		log:        log,
		in:         make(chan Request, 256),
		link:       map[string]string{},
		linkAge:    map[string]time.Time{},
	}, nil
}

// Submit queues a file for snapshotting. Non-blocking: returns false (and
// increments dropped) if the buffer is full, and also returns false after Close
// (no-op). Safe against Close: the closed check and the channel send happen
// under closedMu, so a send can never race close(s.in) into a panic.
func (s *Snapshotter) Submit(r Request) bool {
	s.closedMu.Lock()
	if s.closed {
		s.closedMu.Unlock()
		return false
	}
	select {
	case s.in <- r:
		s.wg.Add(1)
		s.closedMu.Unlock()
		return true
	default:
		s.closedMu.Unlock()
		s.dropped.Add(1)
		s.log.Warn("snapshot buffer full; request dropped", "path", r.Path)
		return false
	}
}

// Run drives the copy worker until ctx is cancelled OR the channel is closed
// (Close). On ctx-cancel it returns immediately (pending requests are lost —
// best-effort). On Close it drains remaining requests then returns.
func (s *Snapshotter) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			s.log.Info("snapshotter stopping (context cancelled)",
				"captured", s.captured.Load(), "lostrace", s.lostRace.Load(), "dropped", s.dropped.Load())
			return
		case r, ok := <-s.in:
			if !ok {
				s.log.Info("snapshotter drained and stopping",
					"captured", s.captured.Load(), "lostrace", s.lostRace.Load(), "dropped", s.dropped.Load())
				return
			}
			s.capture(r)
		}
	}
}

// Close shuts down the worker gracefully: the request channel is closed so Run
// drains remaining copies and returns. Idempotent. After Close, Submit is a
// no-op (returns false). Call this AFTER starting Run, typically via defer.
func (s *Snapshotter) Close() {
	s.closedMu.Lock()
	defer s.closedMu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.in)
}

// Wait blocks until every Submit-ed (non-dropped) request has been processed.
// Primarily for tests; in production the worker runs for the daemon lifetime.
func (s *Snapshotter) Wait() { s.wg.Wait() }

// Captured returns the count of files successfully copied (ok or truncated).
func (s *Snapshotter) Captured() uint64 { return s.captured.Load() }

// LostRace returns the count of files that were gone before the copy (the
// best-effort miss count — Layer B backstops these).
func (s *Snapshotter) LostRace() uint64 { return s.lostRace.Load() }

// Dropped returns the count of requests dropped due to a full buffer.
func (s *Snapshotter) Dropped() uint64 { return s.dropped.Load() }

// capture performs one snapshot: evict if over cap, open the source (with
// retries for transient locks), copy with sha256 + truncation, write content +
// manifest. Never panics (defers wg.Done).
func (s *Snapshotter) capture(r Request) {
	defer s.wg.Done()

	// Enforce the vault size cap before adding a new capture.
	if s.totalMax > 0 {
		s.evictIfNeeded()
	}

	capDir := s.uniqueDir(r)
	if err := os.MkdirAll(capDir, 0o755); err != nil {
		s.log.Warn("snapshot: create capture dir failed", "dir", capDir, "err", err)
		return
	}

	mf := manifest{
		CapturedPath:  r.Path,
		RecordID:      r.RecordID,
		CreatingImage: r.Image,
		ParentImage:   r.ParentImage,
		CommandLine:   r.CmdLine,
		User:          r.User,
		TimeCaptured:  time.Now().UTC().Format(time.RFC3339Nano),
		Status:        "lost-race", // overwritten on success
		ViaArchive:    r.IsArchive,
	}

	// Open with retries: the file may be briefly locked mid-create. The
	// platform openForCopy uses full share access so a held writer (Cursor
	// mid-write) doesn't block us — retries are mainly for the rare case where
	// the handle isn't ready yet. A "not exist" error is not retried (lost race).
	var rc io.ReadCloser
	var openErr error
	for attempt := 0; attempt < 10; attempt++ {
		rc, openErr = openForCopy(r.Path)
		if openErr == nil {
			break
		}
		if isNotExist(openErr) {
			break // file is gone — no point retrying
		}
		time.Sleep(10 * time.Millisecond)
	}

	if openErr != nil {
		// Lost the race: file was deleted before we could read it. Write the
		// manifest anyway so the operator knows the create was observed (and
		// Layer B's archive can be cross-referenced by record_id/time).
		s.lostRace.Add(1)
		s.writeManifest(capDir, mf)
		s.indexCaptured(r.Path, capDir)
		s.log.Debug("snapshot: lost race (file gone)",
			"path", r.Path, "rec", r.RecordID, "err", openErr)
		return
	}
	defer rc.Close()

	// Copy with sha256, capping at perFileMax if set. The content file has NO
	// extension so it can't be executed by accident from the vault.
	contentPath := filepath.Join(capDir, "content")
	f, err := os.OpenFile(contentPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		// We already created capDir above, so mirror the lost-race bookkeeping
		// (manifest + back-link index + miss counter) instead of orphaning an
		// empty dir. Layer B's archive can still cross-reference it by
		// record_id/time. (mf.Status is still the initial "lost-race".)
		s.log.Warn("snapshot: create content file failed", "path", contentPath, "err", err)
		mf.Status = "lost-race"
		s.writeManifest(capDir, mf)
		s.indexCaptured(r.Path, capDir)
		s.lostRace.Add(1)
		return
	}

	src := io.Reader(rc)
	if s.perFileMax > 0 {
		src = io.LimitReader(rc, s.perFileMax)
	}
	h := sha256.New()
	n, err := io.Copy(f, io.TeeReader(src, h))
	f.Close()
	if err != nil {
		s.log.Warn("snapshot: copy failed", "path", r.Path, "err", err)
		mf.Status = "lost-race"
		s.writeManifest(capDir, mf)
		s.indexCaptured(r.Path, capDir)
		s.lostRace.Add(1)
		return
	}

	mf.Size = n
	mf.SHA256 = hex.EncodeToString(h.Sum(nil))
	mf.Status = "ok"
	if s.perFileMax > 0 && n >= s.perFileMax {
		// We may have stopped early. Probe the source for extra bytes: if the
		// LimitReader hit the cap but the file had more, it was truncated.
		if extra, _ := io.Copy(io.Discard, io.LimitReader(rc, 1)); extra > 0 {
			mf.Status = "truncated"
		}
	}
	s.captured.Add(1)
	s.writeManifest(capDir, mf)
	s.indexCaptured(r.Path, capDir)
	s.log.Info("snapshot: captured",
		"path", r.Path, "rec", r.RecordID, "bytes", n, "status", mf.Status,
		"sha256", mf.SHA256[:min(12, len(mf.SHA256))])
}

// uniqueDir builds a vault-relative capture dir name unique by timestamp +
// recordID + nonce.
func (s *Snapshotter) uniqueDir(r Request) string {
	stamp := time.Now().Format("20060102-150405.000")
	nonce := randHex(4)
	return filepath.Join(s.dir, fmt.Sprintf("%s_%d_%s", stamp, r.RecordID, nonce))
}

// writeManifest writes manifest.json into capDir. Best-effort on error (logs).
func (s *Snapshotter) writeManifest(capDir string, mf manifest) {
	b, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(capDir, "manifest.json"), b, 0o600); err != nil {
		s.log.Warn("snapshot: write manifest failed", "dir", capDir, "err", err)
	}
}

// linkMax bounds the in-memory capture->dir index. Generous: at ~10 cursor
// scripts/day, 4096 slots cover weeks of captures within the TTL window.
const linkMax = 4096

// linkTTL is how long a captured path stays in the back-link index. 10 min is
// ample for the cursor case (file create -> script run -> alert fire is <1s);
// the TTL only matters if the detection pipeline is very slow.
const linkTTL = 10 * time.Minute

// indexCaptured records path -> capDir in the back-link index, so a later alert
// referencing path can stamp its hid into that capture's manifest. Called by
// the capture worker after every writeManifest (ok, truncated, AND lost-race —
// a lost-race manifest is still worth back-linking: it tells the operator
// "we saw the create but couldn't copy; here's the alert that references it,
// go check Layer B's archive"). Evicts expired/oldest entries to stay bounded.
func (s *Snapshotter) indexCaptured(path, capDir string) {
	np := pathnorm.NormalizePath(path)
	if np == "" {
		return
	}
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	now := time.Now()
	// lazy TTL eviction
	for p, t := range s.linkAge {
		if now.Sub(t) > linkTTL {
			delete(s.link, p)
			delete(s.linkAge, p)
		}
	}
	// enforce cap (evict oldest if full)
	for len(s.link) >= linkMax {
		var oldest string
		var oldestT time.Time
		for p, t := range s.linkAge {
			if oldest == "" || t.Before(oldestT) {
				oldest = p
				oldestT = t
			}
		}
		delete(s.link, oldest)
		delete(s.linkAge, oldest)
	}
	s.link[np] = capDir
	s.linkAge[np] = now
}

// LinkHit stamps hid into the manifest of any capture whose path is referenced
// by the hit's cmdline (substring) or target file (exact). Called from
// handleEvent's hit loop. Returns the count of manifests updated. Best-effort:
// a missing manifest (evicted from disk) is silently skipped; an already-linked
// manifest is not overwritten (first-write-wins — multiple rules firing on the
// same event get distinct hids; the first links, the rest are findable in
// ALERTS.log by searching for the captured_path).
//
// Matching: the captured path was normalized at index time (lowercase,
// backslash). The cmdline is normalized the same way for a case-insensitive
// substring match — this is how a powershell cmdline containing
// "-File C:\...\Temp\ps-script-<GUID>.ps1" matches the indexed EID-11 path.
// targetFile is matched exactly (normalized) for EID-11 hits like PERSIST-004
// where the hit's TargetFile IS the captured path.
//
// Concurrency: must NOT read s.link outside linkMu. indexCaptured writes the
// map from the snapshot worker goroutine, and len()/range on a map are unsafe
// concurrent with writes. The empty-index case is handled by the locked range
// (no-op) plus a post-lock len(dirs) check — a bare `len(s.link) == 0`
// fast-path here raced the worker (caught by -race in the snapshot-wiring test).
func (s *Snapshotter) LinkHit(hid, cmdline, targetFile string) int {
	if hid == "" || (cmdline == "" && targetFile == "") {
		return 0
	}
	nc := pathnorm.NormalizePath(cmdline)
	nt := pathnorm.NormalizePath(targetFile)

	s.linkMu.Lock()
	var dirs []string
	for path, dir := range s.link {
		if (nc != "" && strings.Contains(nc, path)) || (nt != "" && nt == path) {
			dirs = append(dirs, dir)
		}
	}
	s.linkMu.Unlock()
	if len(dirs) == 0 {
		return 0
	}

	count := 0
	for _, dir := range dirs {
		if s.updateManifestHID(dir, hid) {
			count++
		}
	}
	if count > 0 {
		s.log.Info("snapshot: back-linked hid to capture", "hid", hid, "count", count)
	}
	return count
}

// updateManifestHID reads manifest.json in dir, sets LinkedHID, writes it back.
// Returns false if the manifest is missing, unreadable, or already linked.
func (s *Snapshotter) updateManifestHID(dir, hid string) bool {
	mp := filepath.Join(dir, "manifest.json")
	b, err := os.ReadFile(mp)
	if err != nil {
		return false
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return false
	}
	if m.LinkedHID != "" {
		return false // already linked — first write wins
	}
	m.LinkedHID = hid
	b, err = json.MarshalIndent(m, "", "  ")
	if err != nil {
		return false
	}
	if err := os.WriteFile(mp, b, 0o600); err != nil {
		s.log.Warn("snapshot: back-link manifest write failed", "dir", dir, "err", err)
		return false
	}
	return true
}

// evictIfNeeded removes oldest capture dirs until the vault is under the total
// cap. Oldest = earliest mtime on the capture dir. Never evicts the dir we're
// about to create (it doesn't exist yet).
func (s *Snapshotter) evictIfNeeded() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	type fi struct {
		path string
		mt   time.Time
	}
	var dirs []fi
	var total int64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(s.dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		sz := dirSize(p)
		total += sz
		dirs = append(dirs, fi{p, info.ModTime()})
	}
	// sort oldest first
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].mt.Before(dirs[j].mt) })
	for _, d := range dirs {
		if total < s.totalMax {
			break
		}
		sz := dirSize(d.path)
		if err := os.RemoveAll(d.path); err == nil {
			total -= sz
			s.log.Info("snapshot: evicted old capture (vault over cap)", "dir", d.path, "freed", sz)
		}
	}
}

// dirSize sums the bytes of all regular files under root (recursive).
func dirSize(root string) int64 {
	var total int64
	filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// randHex returns n random bytes as a 2n-char hex string; falls back to a
// timestamp suffix if crypto/rand fails (should not happen in practice).
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// manifest is the JSON sidecar written beside each captured content file.
type manifest struct {
	CapturedPath  string `json:"captured_path"`
	RecordID      uint64 `json:"record_id"`
	CreatingImage string `json:"creating_image,omitempty"`
	ParentImage   string `json:"parent_image,omitempty"`
	CommandLine   string `json:"commandline,omitempty"`
	User          string `json:"user,omitempty"`
	TimeCaptured  string `json:"time_captured"`
	SHA256        string `json:"sha256,omitempty"`
	Size          int64  `json:"size"`
	Status        string `json:"status"`                // ok | truncated | lost-race
	ViaArchive    bool   `json:"via_archive,omitempty"` // true = captured from Sysmon FileDelete archive (EID 23), not original path
	LinkedHID     string `json:"linked_hid,omitempty"`  // filled by A.4 when an alert names this path
}

// FindArchived searches a Sysmon FileDelete archive directory for a file whose
// name contains baseName, returning the full path of the most-recently-modified
// match. Returns "" if nothing is found.
//
// Sysmon archives deleted files (matched by <FileDelete> include rules) to an
// ArchiveDirectory before the delete syscall returns. The archived copy is
// permanent (until cleaned), so poller latency doesn't matter — by the time we
// process EID 23 (1-3s late), the archive copy is still there. We search by
// base-name substring (not exact path) because Sysmon's archive naming scheme
// preserves the original filename somewhere in the archived path.
func FindArchived(archiveDir, baseName string) string {
	if archiveDir == "" || baseName == "" {
		return ""
	}
	baseLower := strings.ToLower(baseName)
	var bestPath string
	var bestTime time.Time
	_ = filepath.WalkDir(archiveDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.Contains(strings.ToLower(d.Name()), baseLower) {
			info, err := d.Info()
			if err == nil && info.ModTime().After(bestTime) {
				bestPath = path
				bestTime = info.ModTime()
			}
		}
		return nil
	})
	return bestPath
}

// NewestArchiveFile returns the most-recently-modified file in archiveDir, or ""
// if empty/unreadable.
//
// Sysmon's FileDelete archive names files by an internal hash identifier
// (e.g. 2A80FB99CD7A...ps1), NOT the original filename, so FindArchived's
// base-name matching is useless against the archive. Instead, since our
// FileDelete include rules match ONLY our capture patterns, every file in the
// archive is one we want — and the one written most recently corresponds to the
// EID 23 we're currently processing (it was archived at delete-time, which
// fired this event). We return the newest file.
//
// ponytail ceiling: if multiple matching files are deleted in the same poller
// interval (a burst), only the single newest is captured per EID 23. Rare for
// the single-ps-script-at-a-time Cursor pattern; acceptable for v1. Upgrade
// path: capture all files with mtime newer than the last-seen archive mtime.
func NewestArchiveFile(archiveDir string) string {
	if archiveDir == "" {
		return ""
	}
	var bestPath string
	var bestTime time.Time
	_ = filepath.WalkDir(archiveDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil && info.ModTime().After(bestTime) {
			bestPath = path
			bestTime = info.ModTime()
		}
		return nil
	})
	return bestPath
}
